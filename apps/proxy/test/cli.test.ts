// P1-15/16/19 through the real CLI: `fr-proxy run --listen host:port` serves Streamable HTTP, a
// non-loopback bind without a token refuses to start, and no body content reaches logs or disk (R10).
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createCanary } from "@afr/log";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { expect, test } from "vitest";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const UPSTREAM = `"${process.execPath}" "${here("./fixtures/upstream-server.mjs")}" --stdio`;

function cli(args: string[], extraEnv: Record<string, string> = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "afr-cli-"));
  const p = spawn(
    process.execPath,
    [
      "--no-warnings",
      "--import",
      here("../../../tools/ts/register.mjs"),
      here("../src/cli.ts"),
      ...args,
    ],
    {
      env: {
        PATH: process.env.PATH ?? "",
        HOME: dataDir,
        AFR_DATA_DIR: dataDir,
        AFR_LOG_LEVEL: "warn",
        ...extraEnv,
      },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let stderr = "";
  p.stderr?.on("data", (d: Buffer) => {
    stderr += d;
  });
  return { p, dataDir, stderr: () => stderr };
}

/** Resolves with the URL from the "listening <url>" line. */
function listening({ p, stderr }: ReturnType<typeof cli>) {
  return new Promise<string>((resolve, reject) => {
    p.stderr?.on("data", () => {
      const m = /listening (\S+)/.exec(stderr());
      if (m?.[1]) resolve(m[1]);
    });
    p.once("exit", () => reject(new Error(`exited early: ${stderr()}`)));
  });
}

const exited = (p: ChildProcess) => new Promise<number | null>((r) => p.once("exit", r));

test("run --listen 127.0.0.1:0 serves MCP over HTTP and exits 0 on SIGTERM", async () => {
  const c = cli(["run", "--listen", "127.0.0.1:0", "--upstream", UPSTREAM]);
  const { p } = c;
  const url = await listening(c);
  const client = new Client({ name: "cli-e2e", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(url)) as Transport);
  expect((await client.callTool({ name: "echo", arguments: { message: "hi" } })).content).toEqual([
    { type: "text", text: "Echo: hi" },
  ]);
  await client.close();
  const code = exited(p);
  p.kill("SIGTERM");
  expect(await code).toBe(0);
}, 30_000);

test("run --listen 0.0.0.0 without a token refuses to start", async () => {
  const c = cli(["run", "--listen", "0.0.0.0:0", "--upstream", UPSTREAM]);
  expect(await exited(c.p)).not.toBe(0);
  expect(c.stderr()).toMatch(/non-loopback/);
}, 30_000);

const filesUnder = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));

test("R10: trace-level logs and the data dir never contain tool args or results", async () => {
  const canary = createCanary();
  const c = cli(["run", "--listen", "127.0.0.1:0", "--upstream", UPSTREAM], {
    AFR_LOG_LEVEL: "trace",
  });
  const client = new Client({ name: "cli-canary", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(await listening(c))) as Transport);
  const r = await client.callTool({ name: "echo", arguments: { message: canary.value } });
  expect(r.content).toEqual([{ type: "text", text: `Echo: ${canary.value}` }]);
  await client.callTool({ name: "fail", arguments: { secret: canary.value } });
  await client.callTool({ name: "nope", arguments: { secret: canary.value } }).catch(() => {});
  await client.close();
  const code = exited(c.p);
  c.p.kill("SIGTERM");
  expect(await code).toBe(0);
  canary.assertAbsent(c.stderr(), ...filesUnder(c.dataDir).map((f) => readFileSync(f, "latin1")));
}, 30_000);
