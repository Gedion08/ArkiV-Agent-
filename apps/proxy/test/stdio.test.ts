// End-to-end: a real MCP client spawns `fr-proxy run --upstream "<node server>"` over stdio (dev quick mode).
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyRecords } from "@afr/core";
import { parseConfig, Recorder } from "@afr/recorder";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { expect, test } from "vitest";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

test("stdio↔stdio proxy records 100 tool calls into a verifiable journal", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "afr-e2e-"));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      "--no-warnings",
      "--import",
      here("../../../tools/ts/register.mjs"),
      here("../src/cli.ts"),
      "run",
      "--name",
      "ref",
      "--upstream",
      `"${process.execPath}" "${here("./fixtures/upstream-server.mjs")}" --stdio`,
    ],
    env: {
      PATH: process.env.PATH ?? "",
      HOME: dataDir,
      AFR_DATA_DIR: dataDir,
      AFR_LOG_LEVEL: "warn",
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "e2e", version: "1.0.0" });
  await client.connect(transport);
  for (let i = 0; i < 100; i++) {
    const r = await client.callTool({ name: "echo", arguments: { message: `m${i}` } });
    expect(r.content).toEqual([{ type: "text", text: `Echo: m${i}` }]);
  }
  await client.close();
  await new Promise((r) => setTimeout(r, 500)); // proxy writes session_end on stdin EOF

  const agentId = readFileSync(join(dataDir, "dev-agent-id"), "utf8").trim();
  const config = parseConfig(
    { version: 1, agent: { id: agentId }, data_dir: dataDir, delegation: { mode: "operator_env" } },
    {},
  );
  const rec = await Recorder.start({
    config,
    env: { AFR_OPERATOR_KEY: readFileSync(join(dataDir, "dev-operator.key"), "utf8").trim() },
    autoRotate: false,
  });
  const recs = [...rec.journal.iterate()];
  const types = recs.map((r) => r.type);
  expect(types.filter((t) => t === "tool_call")).toHaveLength(100);
  expect(types.filter((t) => t === "tool_result")).toHaveLength(100);
  expect(recs.length).toBeGreaterThanOrEqual(200);
  expect(types.slice(0, 2)).toEqual(["session_start", "note"]);
  expect(recs.find((r) => r.type === "session_end")?.header.meta?.reason).toBe("downstream_closed");
  expect(
    await verifyRecords(recs.map((r) => ({ header: r.header, sig: r.sig, hash: r.hash }))),
  ).toEqual([]);
  await rec.close();
}, 120_000);
