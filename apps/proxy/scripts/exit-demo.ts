// P1 exit demo (docs/03-phases/P1-recorder-core.md): fr-proxy in front of the MCP "everything" server.
// 100 tool calls → ≥ 200 records → `fr journal verify` passes; kill -9 mid-call → restart → chain continues.
// Run: node --no-warnings --import tools/ts/register.mjs apps/proxy/scripts/exit-demo.ts
// Needs network for the first npx download (set npm_config_cache to keep it out of ~/.npm).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const REGISTER = here("../../../tools/ts/register.mjs");
const UPSTREAM = "npx -y @modelcontextprotocol/server-everything@2.1.0";
const dataDir = mkdtempSync(join(tmpdir(), "afr-exit-"));
const env: Record<string, string> = {
  PATH: process.env.PATH ?? "",
  HOME: process.env.HOME ?? dataDir,
  AFR_DATA_DIR: dataDir,
  AFR_LOG_LEVEL: "warn",
  npm_config_ignore_scripts: "true",
  ...(process.env.npm_config_cache ? { npm_config_cache: process.env.npm_config_cache } : {}),
};

async function connect() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      "--no-warnings",
      "--import",
      REGISTER,
      here("../src/cli.ts"),
      "run",
      "--name",
      "everything",
      "--upstream",
      UPSTREAM,
    ],
    env,
    stderr: "ignore",
  });
  const client = new Client({ name: "exit-demo", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

async function calls(client: Client, n: number, tag: string) {
  const ms: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    const r = await client.callTool({ name: "echo", arguments: { message: `${tag}${i}` } });
    ms.push(performance.now() - t0);
    assert.match(JSON.stringify(r.content), new RegExp(`${tag}${i}`));
  }
  return ms;
}

function journalVerify() {
  const r = spawnSync(
    process.execPath,
    ["--no-warnings", "--import", REGISTER, here("../../cli/src/cli.ts"), "journal", "verify"],
    {
      env,
      encoding: "utf8",
    },
  );
  return { code: r.status, report: JSON.parse(r.stdout) };
}

const pct = (xs: number[], p: number) =>
  [...xs].sort((a, b) => a - b)[Math.floor(xs.length * p)]?.toFixed(1);

// 1. 100 calls through the proxy
const a = await connect();
const tools = (await a.client.listTools()).tools.map((t) => t.name);
assert.ok(tools.includes("echo"), `echo tool missing: ${tools}`);
const ms = await calls(a.client, 100, "m");
await a.client.close();
await new Promise((r) => setTimeout(r, 1000)); // session_end on stdin EOF
const v1 = journalVerify();
assert.equal(v1.code, 0, JSON.stringify(v1.report.findings));
assert.ok(v1.report.records >= 200, `records ${v1.report.records}`);
console.log(
  `1. ${tools.length} tools; 100 calls → ${v1.report.records} records, verify ok; round trip p50 ${pct(ms, 0.5)} ms p99 ${pct(ms, 0.99)} ms`,
);

// 2. kill -9 with a call in flight, then restart
const b = await connect();
await calls(b.client, 20, "k");
const inflight = b.client
  .callTool({ name: "echo", arguments: { message: "inflight" } })
  .catch(() => "killed");
process.kill(b.transport.pid as number, "SIGKILL");
await inflight;
await b.client.close().catch(() => {});
const c = await connect();
await calls(c.client, 10, "r");
await c.client.close();
await new Promise((r) => setTimeout(r, 1000));
const v2 = journalVerify();
assert.equal(v2.code, 0, JSON.stringify(v2.report.findings));
assert.equal(v2.report.sessions.length, 3);
assert.equal(v2.report.seqRange[0], "0");
assert.equal(
  BigInt(v2.report.seqRange[1]) + 1n,
  BigInt(v2.report.records),
  "seq range is contiguous",
);
console.log(
  `2. after kill -9 + restart: ${v2.report.records} records, seq ${v2.report.seqRange.join("..")}, ${v2.report.sessions.length} sessions, verify ok, findings ${JSON.stringify(v2.report.findings)}`,
);
console.log(`journal: ${v2.report.path}`);
