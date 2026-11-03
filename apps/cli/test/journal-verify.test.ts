// P1-16 `fr journal verify`. Tamper detection itself is covered in packages/recorder verify-journal.test.ts.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, Recorder } from "@afr/recorder";
import { expect, test } from "vitest";
import { main } from "../src/index.js";

const OPERATOR = { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02` };

async function journal(agentId = "eip155:84532:0x00000000000000000000000000000000000a8004:7") {
  const dir = mkdtempSync(join(tmpdir(), "afr-fr-"));
  const config = parseConfig(
    { version: 1, agent: { id: agentId }, data_dir: dir, delegation: { mode: "operator_env" } },
    {},
  );
  const rec = await Recorder.start({ config, env: OPERATOR, autoRotate: false });
  rec.capture({ type: "tool_call", tool: { server: "s", name: "echo" }, body: { args: { m: 1 } } });
  const path = rec.status().journalPath;
  await rec.close();
  return { dir, path };
}

async function run(argv: string[], env: NodeJS.ProcessEnv = {}) {
  let out = "";
  let err = "";
  const code = await main(
    argv,
    env,
    (s) => {
      out += s;
    },
    (s) => {
      err += s;
    },
  );
  return { code, out, err };
}

test("passes on an intact journal", async () => {
  const { path } = await journal();
  const r = await run(["journal", "verify", "--journal", path]);
  expect(r.code).toBe(0);
  expect(JSON.parse(r.out)).toMatchObject({ ok: true, records: 3, findings: [] });
});

test("defaults to the fr-proxy dev identity in AFR_DATA_DIR", async () => {
  const agentId = "local:4b1f2c4e-8a3d-4f6b-9c2e-1d5a7b9e0f12";
  const { dir } = await journal(agentId);
  writeFileSync(join(dir, "dev-agent-id"), agentId);
  const r = await run(["journal", "verify"], { AFR_DATA_DIR: dir });
  expect(r.code).toBe(0);
  expect(JSON.parse(r.out).agentId).toBe(agentId);
});

test("missing journal and bad usage exit 2", async () => {
  const missing = await run(["journal", "verify", "--journal", "/nonexistent/j.sqlite"]);
  expect(missing).toMatchObject({ code: 2, err: expect.stringMatching(/JOURNAL_NOT_FOUND/) });
  expect((await run(["nope"])).code).toBe(2);
});
