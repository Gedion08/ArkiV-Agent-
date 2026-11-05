// W5 (L6 §10): the log auditor over Arkiv batches → the right alerts. The batch-level tampering is the
// verifier's V1/V5 fixture (packages/verifier/test/fixtures); the record-level negative vectors need
// plaintext, which the hosted auditor never has.
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";
import {
  Agent,
  frameRecord,
  T0,
  VECTOR_SK,
} from "../../../packages/verifier/test/fixtures/agent.js";
import { auditLane, GAP_WAIT_S, MemoryAlerts, MemoryWatcherDb } from "../src/index.js";

const SK2 = `0x${"00".repeat(31)}02` as Hex;
const SK3 = `0x${"00".repeat(31)}03` as Hex;
const SPAM = `0x${"00".repeat(31)}66` as Hex;
const AGENT_UUID = "agent-1";

async function world(n = 1) {
  const a = new Agent();
  // Arkiv's clock just after the fixture's delegation starts (T0 − 60 s)
  a.chain.block = (T0 + 100n - BigInt(a.chain.genesisTs)) / 2n;
  await a.delegate(VECTOR_SK);
  for (let i = 0; i < n; i++) await a.batch(0, 3, VECTOR_SK);
  const db = new MemoryWatcherDb();
  const alerts = new MemoryAlerts();
  const audit = () =>
    auditLane({
      db,
      store: a.store,
      identity: a.identity,
      alerts,
      agentId: AGENT_UUID,
      agent: a.agentId,
      lane: 0,
    });
  const types = () => [...alerts.alerts.values()].map((x) => x.type).sort();
  return { a, db, alerts, audit, types };
}

describe("log auditor (W5)", () => {
  test("a clean lane: no alerts, the cursor follows the chain, nothing is checked twice", async () => {
    const w = await world(3);
    expect(await w.audit()).toBe(3);
    expect(w.types()).toEqual([]);
    expect(await w.db.auditCursor(AGENT_UUID, 0)).toEqual({
      next: 9n,
      root: w.a.tip.get(0)?.chainRoot,
    });
    expect(await w.audit()).toBe(0);
    await w.a.batch(0, 3, VECTOR_SK);
    expect(await w.audit()).toBe(1);
    expect(w.types()).toEqual([]);
  });

  test("SEQ_GAP once the later batch is older than the wait; the chain check resumes after it", async () => {
    const w = await world(1);
    w.a.records(0, 3, VECTOR_SK); // made, never uploaded
    await w.a.batch(0, 3, VECTOR_SK);
    expect(await w.audit()).toBe(1); // [0,2]; [6,8] may still be in flight behind [3,5]
    expect(w.types()).toEqual([]);
    w.a.chain.block += GAP_WAIT_S / 2n + 1n;
    expect(await w.audit()).toBe(1);
    expect(w.types()).toEqual(["SEQ_GAP"]); // no BROKEN_CHAIN: [3,5]'s root is unknown
    const gap = w.alerts.open("SEQ_GAP")[0];
    expect(gap?.subject).toMatchObject({ seq_from: "3", seq_to: "5" });
    expect(gap?.dedupeKey).toBe(`SEQ_GAP:${AGENT_UUID}:0:3`);
    expect((await w.db.auditCursor(AGENT_UUID, 0)).next).toBe(9n);
  });

  test("BROKEN_CHAIN: a root that doesn't link; a swapped record hash (Merkle + record sig)", async () => {
    const w = await world(1);
    await w.a.putFrame(
      w.a.seal(0, w.a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK, {
        prevChainRoot: `0x${"77".repeat(32)}`,
      }),
    );
    await w.audit();
    expect(w.alerts.open("BROKEN_CHAIN").map((x) => x.evidence?.details?.checks)).toEqual([
      "CHAIN_BREAK",
    ]);

    const v = await world(1);
    const f = v.a.seal(0, v.a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK);
    (f.pub.records[1] as { hash: Hex }).hash = `0x${"ee".repeat(32)}`;
    await v.a.putFrame(f);
    await v.audit();
    expect(v.alerts.open("BROKEN_CHAIN").map((x) => x.evidence?.details?.checks)).toEqual([
      "MERKLE_MISMATCH,RECORD_SIG",
    ]);
  });

  test("EQUIVOCATION: two delegated forks of one range; a byte-identical copy is fine", async () => {
    const w = await world(1);
    const before = { ...(w.a.tip.get(0) as { seq: bigint; prevHash: Hex; chainRoot: Hex }) };
    const f = await w.a.batch(0, 3, VECTOR_SK);
    await w.a.putFrame(f); // a rollback re-create
    await w.a.delegate(SK2);
    w.a.tip.set(0, before);
    await w.a.batch(0, 3, SK2);
    await w.audit();
    expect(w.types()).toEqual(["EQUIVOCATION"]);
    const e = w.alerts.open("EQUIVOCATION")[0];
    expect(e?.dedupeKey).toBe(`EQUIVOCATION:${AGENT_UUID}:0:3`);
    expect(e?.evidence?.details?.batches?.split(",")).toHaveLength(2);
  });

  test("DELEGATION_MISUSE: a known key outside its delegation; an unknown signer is noise", async () => {
    const w = await world(1);
    await w.a.delegate(SK3, { notBefore: T0 - 86_400n, notAfter: T0 - 7_200n }); // over before Arkiv's now
    const before = { ...(w.a.tip.get(0) as { seq: bigint; prevHash: Hex; chainRoot: Hex }) };
    await w.a.batch(0, 3, SK3);
    w.a.tip.set(0, before);
    await w.a.batch(0, 3, SPAM);
    await w.audit();
    expect(w.types()).toEqual(["DELEGATION_MISUSE"]);
    expect(w.alerts.open()[0]?.evidence?.details).toMatchObject({ reason: "not_delegated" });
    expect((await w.db.auditCursor(AGENT_UUID, 0)).next).toBe(3n); // no valid batch for [3,5] yet
  });

  test("batch flags → POLICY_BREACH, UNAPPROVED_HIGH_VALUE, POLICY_BLOCK", async () => {
    const w = await world(0);
    const f = w.a.seal(0, w.a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK);
    f.pub.flags = { has_tx: true, has_block: true, has_unapproved_tx: true, has_violation: true };
    await w.a.putFrame(f);
    await w.audit();
    expect(w.types()).toEqual(["POLICY_BLOCK", "POLICY_BREACH", "UNAPPROVED_HIGH_VALUE"]);
    // evidence is hashes and seqs only
    expect(w.alerts.open()[0]?.evidence?.last_records?.map((r) => r.seq)).toEqual(["0", "1", "2"]);
  });
});
