#!/usr/bin/env node
// fr-proxy CLI (L2 §5.3). stdout may carry MCP traffic (stdio mode), so logs always go to stderr.
import { parseArgs } from "node:util";
import type { AfrError } from "@afr/core";
import { createLogger, type Logger } from "@afr/log";
import { fileSignatureRequester, Recorder } from "@afr/recorder";
import { delegate, init, status } from "./commands.js";
import { type Resolved, resolveConfig } from "./config.js";
import { startHttpProxy } from "./http.js";
import { createProxy } from "./proxy.js";
import {
  httpUpstream,
  parseListen,
  stdioDownstream,
  stdioUpstream,
  type Transport,
} from "./transport.js";

const USAGE = `usage:
  fr-proxy init     [--out afr.config.yaml] [--agent-id ID] [--lane N] [--data-dir DIR] [--delegation MODE] [--upstream CMD] [--force]
  fr-proxy run      [--config FILE] (--upstream "<command>" | --upstream-url URL) [--listen stdio|host:port] [--name SERVER]
  fr-proxy status   [--config FILE]
  fr-proxy delegate [--config FILE] [--sig 0x… | --sign]

Without --config, a dev identity (local:<uuid>, dev operator key) is used from ~/.afr (or $AFR_DATA_DIR).`;

const OPTIONS = {
  config: { type: "string" },
  upstream: { type: "string" },
  "upstream-url": { type: "string" },
  listen: { type: "string" },
  name: { type: "string" },
  out: { type: "string" },
  "agent-id": { type: "string" },
  lane: { type: "string" },
  "data-dir": { type: "string" },
  delegation: { type: "string" },
  sig: { type: "string" },
  sign: { type: "boolean" },
  force: { type: "boolean" },
  help: { type: "boolean" },
} as const;

const print = (s: string) => process.stdout.write(s);

export async function main(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const log = createLogger({
    name: "fr-proxy",
    level: env.AFR_LOG_LEVEL ?? "info",
    destination: process.stderr,
  });
  let args: ReturnType<
    typeof parseArgs<{ args: string[]; allowPositionals: true; options: typeof OPTIONS }>
  >;
  try {
    args = parseArgs({ args: argv, allowPositionals: true, options: OPTIONS });
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }
  const { positionals, values: v } = args;
  const cmd = positionals[0];
  if (v.help || !cmd) {
    process.stderr.write(`${USAGE}\n`);
    return v.help ? 0 : 2;
  }
  try {
    if (cmd === "init") {
      return await init(
        {
          out: v.out ?? "afr.config.yaml",
          ...(v["agent-id"] ? { agentId: v["agent-id"] } : {}),
          ...(v.lane ? { lane: v.lane } : {}),
          ...(v["data-dir"] ? { dataDir: v["data-dir"] } : {}),
          ...(v.delegation ? { delegation: v.delegation } : {}),
          ...(v.upstream ? { upstream: v.upstream } : {}),
          force: v.force ?? false,
          interactive: process.stdin.isTTY === true,
        },
        (s) => process.stderr.write(s),
      );
    }
    const resolved = resolveConfig(v.config, env);
    if (cmd === "status") return await status(resolved, print);
    if (cmd === "delegate")
      return await delegate(
        resolved,
        { ...(v.sig ? { sig: v.sig } : {}), sign: v.sign ?? false },
        print,
      );
    if (cmd === "run") return await run(resolved, v, log);
  } catch (e) {
    process.stderr.write(
      `${(e as AfrError).code ? `${(e as AfrError).code}: ` : ""}${(e as Error).message}\n`,
    );
    return 2;
  }
  process.stderr.write(`unknown command ${cmd}\n${USAGE}\n`);
  return 2;
}

type Values = Record<string, string | boolean | undefined>;

async function run(r: Resolved, v: Values, log: Logger): Promise<number> {
  const cfgUp = r.config.proxy?.upstreams[0];
  const upCommand = (v.upstream as string | undefined) ?? cfgUp?.command;
  const upUrl = (v["upstream-url"] as string | undefined) ?? cfgUp?.url;
  if (!upCommand === !upUrl)
    throw new Error(
      "give exactly one of --upstream or --upstream-url (or proxy.upstreams in config)",
    );
  const listen = (v.listen as string | undefined) ?? r.config.proxy?.listen ?? "stdio";
  const serverName = (v.name as string | undefined) ?? cfgUp?.name ?? "upstream";
  const tokenEnv = r.config.proxy?.auth_token_env;
  const authToken = tokenEnv ? r.env[tokenEnv] : undefined;
  if (tokenEnv && !authToken)
    throw new Error(`proxy.auth_token_env=${tokenEnv} is set but the variable is empty`);
  if (r.dev)
    log.warn(
      { agentId: r.config.agent.id },
      "no --config: using a dev identity (not for production)",
    );

  const recorder = await Recorder.start({
    config: r.config,
    env: r.env,
    logger: log,
    ...(r.config.delegation.mode === "interactive"
      ? {
          requestSignature: fileSignatureRequester(r.laneDir, {
            timeoutMs: r.config.delegation.timeout_s * 1000,
          }),
        }
      : {}),
  });
  if (r.config.delegation.mode === "interactive") {
    log.warn(
      { request: `${r.laneDir}/delegation-request.json` },
      "waiting for delegation signature: run `fr-proxy delegate`",
    );
  }
  const st = recorder.status();
  log.info(
    { agentId: st.agentId, lane: st.lane, seq: String(st.nextSeq), journal: st.journalPath },
    "recording",
  );
  const upstream = (authorization?: string): Transport =>
    upCommand
      ? stdioUpstream(upCommand, r.env)
      : httpUpstream(upUrl as string, cfgUp?.forward_auth ? authorization : undefined);

  return await new Promise<number>((resolve) => {
    let done = false;
    let closeSurface: () => Promise<void> = async () => {};
    const shutdown = async (reason: string, code = 0) => {
      if (done) return;
      done = true;
      await closeSurface();
      await recorder
        .close(reason)
        .catch((e: AfrError) => log.error({ code: e.code }, "close failed"));
      resolve(code);
    };
    process.once("SIGINT", () => void shutdown("sigint"));
    process.once("SIGTERM", () => void shutdown("sigterm"));

    if (listen === "stdio") {
      const proxy = createProxy({
        recorder,
        downstream: stdioDownstream(),
        upstream: upstream(),
        serverName,
        log,
        onClose: () => void shutdown("transport_closed"),
      });
      closeSurface = () => proxy.close();
      // StdioServerTransport doesn't report stdin EOF as a close; the agent going away must end the session
      process.stdin.once("end", () => void shutdown("downstream_closed"));
      proxy.start().catch((e: Error) => {
        log.error({ err: e.name }, "failed to start upstream");
        void shutdown("start_failed", 1);
      });
    } else {
      const { host, port } = parseListen(listen);
      startHttpProxy({
        recorder,
        host,
        port,
        serverName,
        log,
        ...(authToken ? { authToken } : {}),
        upstream: (headers) =>
          upstream(typeof headers.authorization === "string" ? headers.authorization : undefined),
      }).then(
        (http) => {
          closeSurface = () => http.close();
          log.info({ url: http.url }, "listening");
          process.stderr.write(`listening ${http.url}\n`);
        },
        (e: Error) => {
          log.error({ err: e.message }, "failed to listen");
          void shutdown("start_failed", 1);
        },
      );
    }
  });
}

main(process.argv.slice(2)).then((code) => process.exit(code));
