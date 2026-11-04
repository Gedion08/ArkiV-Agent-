// P2-11: epoch KEK lifecycle + keygrants before the first batch of an epoch (L4 §2, §5, §7).
import { existsSync, readFileSync } from "node:fs";
import { agentKey, verifyTyped } from "@afr/core";
import { KEK_MAX_WRAPS, kekIdFor } from "@afr/crypto";
import type { Logger } from "@afr/log";
import { decodeCanonical, decodeFrame, MemoryChain, MemoryStore } from "@afr/store";
import { bytesToHex, type Hex, keccak256 } from "viem";
import { describe, expect, test } from "vitest";
import { identityChainId, type KeygrantSealer, Recorder } from "../src/index.js";
import { AGENT, env, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const R1 = `0x${"01".repeat(32)}` as Hex;
const R2 = `0x${"02".repeat(32)}` as Hex;
const NOV_2026 = Date.UTC(2026, 10, 15); // epoch 352
const DEC_2026 = Date.UTC(2026, 11, 1); // epoch 368

/** Test stand-in for HPKE (P2-07 part 2): shape-correct, NOT a real seal. */
const fakeSeal: KeygrantSealer = (kek, reader) => ({
  enc: new Uint8Array(32).fill(Number.parseInt(reader.slice(2, 4), 16)),
  ct: new Uint8Array(48).fill(kek.epochId & 0xff),
});

function harness(readers: Hex[] = [], sealKeygrant: KeygrantSealer | null = fakeSeal) {
  const config = tmpConfig({ encryption: { readers } });
  const chain = new MemoryChain();
  const store = new MemoryStore(chain, WRITER);
  const clock = { now: NOV_2026 };
  const logged: string[] = [];
  const log = (o: unknown) => logged.push(JSON.stringify(o));
  const logger = { warn: log, error: log, info: log, debug: log } as unknown as Logger;
  const start = () =>
    Recorder.start({
      config,
      env,
      autoRotate: false,
      now: () => clock.now,
      logger,
      upload: { store, tickMs: 3_600_000, ...(sealKeygrant ? { sealKeygrant } : {}) },
    });
  const schemas = () => [...chain.rows.values()].map((r) => r.schema);
  const batchEpochs = () =>
    [...chain.rows.values()]
      .filter((r) => r.schema === "afr.batch.v1")
      .map((r) => decodeFrame(r.payload).pub.epoch_id);
  return { config, chain, store, clock, logged, start, schemas, batchEpochs };
}

describe("P2-11 epochs + keygrants", () => {
  test("monthly epoch: KEK sealed at rest, reused across restarts, rotates at the month boundary", async () => {
    const h = harness();
    const rec = await h.start();
    await rec.flush();
    const e = rec.journal.latestEpoch();
    expect(e?.epochId).toBe(352);
    const kek = rec.journal.epochKek(352);
    expect(kekIdFor(AK, 352, kek.key)).toBe(e?.kekId);
    await rec.close();

    const again = await h.start(); // same month: same epoch, same KEK
    await again.flush();
    expect(again.journal.latestEpoch()?.epochId).toBe(352);
    expect(bytesToHex(again.journal.epochKek(352).key)).toBe(bytesToHex(kek.key));
    h.clock.now = DEC_2026;
    again.capture({ type: "note", body: { args: {} } });
    await again.flush();
    expect(again.journal.epoch(352)?.rotatedAt).toBeDefined();
    expect(h.batchEpochs().at(-1)).toBe(368);
    await again.close();
  });

  test("manual rotation and the DEK-wrap budget start a new rotation within the month", async () => {
    const h = harness();
    const rec = await h.start();
    await rec.flush();
    rec.rotateEpoch();
    rec.capture({ type: "note", body: { args: {} } });
    await rec.flush();
    expect(h.batchEpochs().slice(-1)).toEqual([353]);
    rec.journal.addWraps(353, KEK_MAX_WRAPS - 100);
    rec.capture({ type: "note", body: { args: {} } });
    await rec.flush();
    expect(h.batchEpochs().slice(-1)).toEqual([354]);
    expect(h.logged.join()).toContain("WRAP_BUDGET");
    await rec.close();
  });

  test("keygrants are published, signed and verified before the epoch's first batch", async () => {
    const h = harness([R2, R1]);
    const rec = await h.start();
    await rec.flush();
    const kinds = h.schemas();
    expect(kinds.slice(0, 2)).toEqual(["afr.keygrant.v1", "afr.keygrant.v1"]);
    expect(kinds.indexOf("afr.batch.v1")).toBe(2);
    const sk = rec.status().sessionKey;
    for (const row of [...h.chain.rows.values()].filter((r) => r.schema === "afr.keygrant.v1")) {
      const g = decodeCanonical(row.payload) as {
        enc: Uint8Array;
        ct: Uint8Array;
        statement: Record<string, unknown>;
        sig: Hex;
      };
      expect(row).toMatchObject({ readonly: true, permissionlessExtension: false, owner: WRITER });
      expect(row.attrs).toMatchObject({ agent_key: AK, epoch_id: 352n, kek_id: g.statement.kekId });
      expect(g.statement.encHash).toBe(keccak256(new Uint8Array([...g.enc, ...g.ct])));
      expect(await verifyTyped(identityChainId(AGENT), "KeyGrant", g.statement, g.sig, sk)).toBe(
        true,
      );
    }
    expect(rec.journal.epoch(352)).toMatchObject({ grantsPublished: true, granted: [R1, R2] });
    await rec.close();
  });

  test("without an HPKE sealer, configured readers hold uploads back (logged once)", async () => {
    const h = harness([R1], null);
    const rec = await h.start();
    await rec.flush();
    await rec.flush();
    expect(h.schemas()).toEqual([]);
    expect(rec.status().batches).toEqual({ prepared: 1 });
    expect(h.logged.filter((l) => l.includes("KEYGRANT_UNAVAILABLE"))).toHaveLength(1);
    await rec.close();
  });

  test("reader added → grant for the current epoch; reader removed → immediate rotation", async () => {
    const h = harness([R1]);
    const rec = await h.start();
    await rec.flush();
    rec.setReaders([R1, R2]);
    rec.capture({ type: "note", body: { args: {} } });
    await rec.flush();
    expect(rec.journal.epoch(352)).toMatchObject({ granted: [R1, R2], grantsPublished: true });
    expect(rec.journal.latestEpoch()?.epochId).toBe(352);
    rec.setReaders([R2]);
    rec.capture({ type: "note", body: { args: {} } });
    await rec.flush();
    expect(rec.journal.latestEpoch()).toMatchObject({ epochId: 353, readers: [R2], granted: [R2] });
    const grants353 = [...h.chain.rows.values()].filter(
      (r) => r.schema === "afr.keygrant.v1" && r.attrs.epoch_id === 353n,
    );
    expect(grants353.map((r) => r.attrs.reader)).toEqual([R2]); // the removed reader gets nothing new
    expect(h.batchEpochs().at(-1)).toBe(353);
    await rec.close();
  });

  test("canary: the raw KEK never reaches the journal files, the store or logs (CLAUDE.md rule 2)", async () => {
    const h = harness([R1]);
    const rec = await h.start();
    await rec.flush();
    const raw = Buffer.from(rec.journal.epochKek(352).key);
    const path = rec.journal.path;
    await rec.close();
    for (const f of [path, `${path}-wal`].filter(existsSync))
      expect(readFileSync(f).includes(raw)).toBe(false);
    for (const r of h.chain.rows.values()) expect(Buffer.from(r.payload).includes(raw)).toBe(false);
    expect(h.logged.join().includes(raw.toString("hex"))).toBe(false);
  });
});
