import Database from "better-sqlite3";
import { expect, test } from "vitest";
import { Recorder } from "../src/recorder.js";
import { verifyJournal } from "../src/verify-journal.js";
import { env, tmpConfig } from "./fixtures/setup.js";

async function journalWith(n: number) {
  const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
  for (let i = 0; i < n; i++)
    rec.capture({ type: "tool_call", tool: { server: "s", name: "t" }, body: { args: { i } } });
  const path = rec.status().journalPath;
  await rec.close();
  return path;
}

test("a clean journal verifies", async () => {
  const r = await verifyJournal(await journalWith(5));
  expect(r).toMatchObject({ ok: true, records: 7, seqRange: ["0", "6"], findings: [] });
  expect(r.sessions).toEqual([{ address: expect.stringMatching(/^0x/), delegation: "signed" }]);
});

test("tampering with a stored header is detected", async () => {
  const path = await journalWith(3);
  const db = new Database(path);
  const row = db.prepare("SELECT header_jcs FROM records WHERE seq = 2").get() as {
    header_jcs: string;
  };
  db.prepare("UPDATE records SET header_jcs = ? WHERE seq = 2").run(
    row.header_jcs.replace('"name":"t"', '"name":"x"'),
  );
  db.close();
  const r = await verifyJournal(path);
  expect(r.ok).toBe(false);
  expect(new Set(r.findings.map((f) => f.code))).toEqual(
    new Set(["HEADER_HASH", "RECORD_SIG", "CHAIN_BREAK"]),
  );
});

test("deleting a row is detected", async () => {
  const path = await journalWith(3);
  const db = new Database(path);
  db.prepare("DELETE FROM records WHERE seq = 1").run();
  db.close();
  expect((await verifyJournal(path)).findings.map((f) => f.code)).toEqual([
    "SEQ_GAP",
    "CHAIN_BREAK",
  ]);
});

test("missing journal", async () => {
  await expect(verifyJournal("/nonexistent/journal.sqlite")).rejects.toThrow(
    expect.objectContaining({ code: "JOURNAL_NOT_FOUND" }),
  );
});
