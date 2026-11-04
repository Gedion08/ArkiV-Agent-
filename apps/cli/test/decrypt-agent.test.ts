// P2-16 tools/scripts/decrypt-agent.ts end to end: a recorder with a configured reader uploads batches
// and keygrants; the script opens them with the reader's `.afrkey`, decrypts and checks every hash.
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  exportReaderBackup,
  generateReaderKey,
  importReaderBackup,
  sealKeygrant,
} from "@afr/crypto";
import { createCanary } from "@afr/log";
import { parseConfig, Recorder } from "@afr/recorder";
import { MemoryChain, MemoryStore } from "@afr/store";
import type { Hex } from "viem";
import { expect, test } from "vitest";
import { run } from "../../../tools/scripts/decrypt-agent.js";

const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const OPERATOR = { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02` };
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const PW = "correct horse battery staple";
const FAST = { m: 64, t: 1, p: 1 };

async function reader(dir: string, name: string) {
  const key = await generateReaderKey();
  const file = join(dir, name);
  writeFileSync(file, JSON.stringify(await exportReaderBackup(key, PW, FAST)));
  return { key, file };
}

/** Records `n` tool calls (the canary in each body) with `readers` configured; returns the store. */
async function recorded(readers: Hex[], n: number, secret: string) {
  const dir = mkdtempSync(join(tmpdir(), "afr-dec-"));
  const chain = new MemoryChain();
  const store = new MemoryStore(chain, WRITER);
  const config = parseConfig(
    {
      version: 1,
      agent: { id: AGENT },
      data_dir: dir,
      delegation: { mode: "operator_env" },
      encryption: { readers },
    },
    {},
  );
  const rec = await Recorder.start({
    config,
    env: OPERATOR,
    autoRotate: false,
    upload: { store, tickMs: 3_600_000, sealKeygrant },
  });
  await rec.delegationReady();
  for (let i = 0; i < n; i++) {
    rec.capture({
      type: "tool_call",
      tool: { server: "s", name: "pay" },
      body: { args: { i, secret } },
    });
    if (i % 2) await rec.flush(); // several batches
  }
  await rec.close(); // uploads the rest, including session_end
  return { dir, chain, store };
}

async function decrypt(argv: string[], store: MemoryStore) {
  const lines: string[] = [];
  const code = await run(argv, { store, passphrase: async () => PW, out: (l) => lines.push(l) });
  return { code, out: lines.join("\n") };
}

test("decrypts every batch with the reader's .afrkey; all hashes check; plaintext only in --out", async () => {
  const canary = createCanary();
  const dir = mkdtempSync(join(tmpdir(), "afr-dec-"));
  const r = await reader(dir, "r.afrkey");
  const h = await recorded([r.key.pub], 5, canary.value);
  const outFile = join(dir, "records.json");
  const res = await decrypt(
    ["decrypt", "--agent", AGENT, "--reader-key", r.file, "--out", outFile, "--writer", WRITER],
    h.store,
  );
  const summary = JSON.parse(res.out);
  expect(summary).toMatchObject({ ok: true, findings: [] });
  expect(summary.batches).toBeGreaterThanOrEqual(2);
  expect(res.code).toBe(0);
  canary.assertAbsent(res.out);

  const records = JSON.parse(readFileSync(outFile, "utf8"));
  expect(records).toHaveLength(summary.records);
  expect(records.map((x: { seq: string }) => x.seq)).toEqual(
    [...Array(records.length).keys()].map(String),
  );
  expect(records.at(-1).header.type).toBe("session_end");
  const calls = records.filter((x: { header: { type: string } }) => x.header.type === "tool_call");
  expect(calls.map((x: { body: { args: { i: number } } }) => x.body.args.i)).toEqual([
    0, 1, 2, 3, 4,
  ]);
  expect(readFileSync(outFile, "utf8")).toContain(canary.value);
  expect(statSync(outFile).mode & 0o777).toBe(0o600);
  // never overwrites
  const again = await decrypt(
    ["decrypt", "--agent", AGENT, "--reader-key", r.file, "--out", outFile],
    h.store,
  );
  expect(again.code).toBe(2);
});

test("another reader has no keygrant: NO_KEYGRANT, nothing decrypted, exit 1", async () => {
  const dir = mkdtempSync(join(tmpdir(), "afr-dec-"));
  const granted = await reader(dir, "a.afrkey");
  const stranger = await reader(dir, "b.afrkey");
  const h = await recorded([granted.key.pub], 1, "x");
  const res = await decrypt(["decrypt", "--agent", AGENT, "--reader-key", stranger.file], h.store);
  expect(res.code).toBe(1);
  const s = JSON.parse(res.out);
  expect(s.records).toBe(0);
  expect(s.findings.map((f: { code: string }) => f.code)).toContain("NO_KEYGRANT");
});

test("a tampered batch payload is reported, not decrypted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "afr-dec-"));
  const r = await reader(dir, "r.afrkey");
  const h = await recorded([r.key.pub], 1, "x");
  const batch = [...h.chain.rows.values()].find((x) => x.schema === "afr.batch.v1");
  const p = batch?.payload as Uint8Array;
  p[p.length - 1] = (p[p.length - 1] as number) ^ 1; // last ct byte
  const res = await decrypt(["decrypt", "--agent", AGENT, "--reader-key", r.file], h.store);
  expect(res.code).toBe(1);
  expect(JSON.parse(res.out).findings[0].code).toBe("FRAME_INVALID");
});

test("keygen writes a 0600 .afrkey that imports with the passphrase; refuses weak passphrases and overwrites", async () => {
  const dir = mkdtempSync(join(tmpdir(), "afr-dec-"));
  const file = join(dir, "new.afrkey");
  const res = await decrypt(["keygen", "--out", file], new MemoryStore(new MemoryChain(), WRITER));
  expect(res.code).toBe(0);
  const backup = JSON.parse(readFileSync(file, "utf8"));
  expect(JSON.parse(res.out).reader).toBe(backup.x25519_pub);
  expect([backup.m, backup.t]).toEqual([65536, 3]);
  expect(statSync(file).mode & 0o777).toBe(0o600);
  expect((await importReaderBackup(backup, PW)).pub).toBe(backup.x25519_pub);
  expect((await decrypt(["keygen", "--out", file], h0())).code).toBe(2);
  const weak = await run(["keygen", "--out", join(dir, "w.afrkey")], {
    passphrase: async () => "short",
    out: () => {},
  });
  expect(weak).toBe(2);
  expect(await run(["nope"], { out: () => {} })).toBe(2);
}, 60_000);

const h0 = () => new MemoryStore(new MemoryChain(), WRITER);
