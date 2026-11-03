// Transport wrappers (risk table P1: isolate MCP SDK transport API differences here).
import {
  StdioClientTransport,
  type StdioServerParameters,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

export type { Transport };

/** Splits a command line with single/double quotes and backslash escapes (no globbing, no variables). */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i] as string;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < line.length) cur += line[++i];
      else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (c === "\\" && i + 1 < line.length) {
      cur += line[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
    }
  }
  if (quote) throw new Error("unterminated quote in upstream command");
  if (has || cur) out.push(cur);
  return out;
}

/** Upstream env: everything the proxy got, minus AFR_* (operator keys must never reach tools). */
export function upstreamEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter(
      (e): e is [string, string] => e[1] !== undefined && !e[0].startsWith("AFR_"),
    ),
  );
}

export function stdioUpstream(command: string, env: NodeJS.ProcessEnv = process.env): Transport {
  const [cmd, ...args] = splitCommand(command);
  if (!cmd) throw new Error("empty upstream command");
  const params: StdioServerParameters = {
    command: cmd,
    args,
    env: upstreamEnv(env),
    stderr: "inherit",
  };
  return new StdioClientTransport(params);
}

export function stdioDownstream(): Transport {
  return new StdioServerTransport();
}

/** Streamable HTTP upstream. `authorization` is forwarded only when the upstream has forward_auth: true. */
export function httpUpstream(url: string, authorization?: string): Transport {
  return new StreamableHTTPClientTransport(new URL(url), {
    ...(authorization ? { requestInit: { headers: { authorization } } } : {}),
  }) as Transport; // SDK omits `| undefined` on optional callbacks
}

/** "host:port" → parts. IPv6 hosts in brackets: "[::1]:7801". */
export function parseListen(listen: string): { host: string; port: number } {
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(listen);
  if (!m) throw new Error(`--listen must be host:port, got ${listen}`);
  return { host: (m[1] ?? m[2]) as string, port: Number(m[3]) };
}
