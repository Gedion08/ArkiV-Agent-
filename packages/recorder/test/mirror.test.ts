// P2-15 mirror mode (L3 §9): every entity confirmed on the primary is copied to the mirror with the same
// bytes; the mirror being down never blocks the primary, and its backlog survives a restart.
import { randomBytes } from "node:crypto";
import { agentKey, batchId } from "@afr/core";
import { createCanary, type Logger } from "@afr/log";
import { type AfrSchemaName, type EvidenceStore, MemoryChain, MemoryStore } from "@afr/store";
import { encodeAbiParameters, type Hex, keccak256 } from "viem";
import { describe, expect, test } from "vitest";
import { Recorder } from "../src/index.js";
import { AGENT, env, ready, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const SCHEMAS: AfrSchemaName[] = ["afr.delegation.v1", "afr.agent.v1", "afr.batch.v1"];
/** The uploader's idempotency key for batch 0, attempt 0. */
const BATCH0_ID = keccak256(
  encodeAbiParameters([{ type: "bytes32" }, { type: "uint32" }], [batchId(AK, 0, 0n), 0]),
);

/** Payloads per schema for this agent, sorted, as hex (order-independent comparison). */
async function contents(store: EvidenceStore) {
  const out: Record<string, string[]> = {};
  for (const schema of SCHEMAS) {
    const got: string[] = [];
    for await (const e of store.query({ schema, where: { agent_key: { eq: AK } } }))
      got.push(Buffer.from(e.payload).toString("hex"));
    out[schema] = got.sort();
  }
  return out;
}

/** A mirror that fails every write while `down` is set. */
function flaky(store: EvidenceStore) {
  const state = { down: true, puts: 0 };
  const proxy = new Proxy(store, {
    get(t, p, r) {
      if (p === "put")
        return (req: Parameters<EvidenceStore["put"]>[0]) => {
          state.puts++;
          if (state.down)
            return Promise.reject(Object.assign(new Error("down"), { code: "ECONNREFUSED" }));
          return t.put(req);
        };
      const v = Reflect.get(t, p, r);
      return typeof v === "function" ? v.bind(t) : v;
    },
  });
  return { store: proxy, state };
}

const capture = () => {
  const logged: string[] = [];
  const log = (o: unknown) => logged.push(JSON.stringify(o));
  return { logged, logger: { warn: log, error: log, info: log, debug: log } as unknown as Logger };
};

function harness(mirror: EvidenceStore | undefined, logger?: Logger) {
  const config = tmpConfig({ store: { kind: "memory", mirror: "postgres" } });
  const primary = new MemoryStore(new MemoryChain(), WRITER);
  const clock = { now: Date.now() };
  const start = () =>
    ready(
      Recorder.start({
        config,
        env,
        autoRotate: false,
        now: () => clock.now,
        ...(logger ? { logger } : {}),
        upload: { store: primary, tickMs: 3_600_000, ...(mirror ? { mirror } : {}) },
      }),
    );
  return { start, primary, clock };
}

const note = (rec: Recorder, i: number) =>
  rec.capture({ type: "note", meta: { event: `n${i}` }, body: { args: { i } } });

describe("P2-15 mirror mode", () => {
  test("every confirmed entity (delegation, profile, batches) lands in the mirror with the same bytes", async () => {
    const mirror = new MemoryStore(new MemoryChain(), WRITER);
    const h = harness(mirror);
    const rec = await h.start();
    for (let i = 0; i < 3; i++) note(rec, i);
    await rec.flush();
    expect(rec.journal.mirrorSize()).toBe(0);
    await rec.close();
    const want = await contents(h.primary);
    expect(want["afr.batch.v1"]?.length).toBeGreaterThanOrEqual(2);
    expect(want["afr.delegation.v1"]).toHaveLength(1);
    expect(want["afr.agent.v1"]).toHaveLength(1);
    expect(await contents(mirror)).toEqual(want);
  });

  test("mirror down: the primary still verifies; the backlog waits (backoff), survives a restart, then drains", async () => {
    const { logged, logger } = capture();
    const f = flaky(new MemoryStore(new MemoryChain(), WRITER));
    const h = harness(f.store, logger);
    const rec = await h.start();
    note(rec, 1);
    await rec.flush();
    expect(rec.journal.batchCounts().verified).toBeGreaterThan(0); // primary unaffected
    expect(rec.journal.mirrorSize()).toBeGreaterThan(0);
    expect(f.state.puts).toBe(1); // the first failure stops the drain
    await rec.flush();
    expect(f.state.puts).toBe(1); // backed off
    expect(logged.filter((l) => l.includes("ECONNREFUSED"))).toHaveLength(1);
    await rec.close();

    f.state.down = false;
    h.clock.now += 60_000;
    const again = await h.start();
    await again.flush();
    expect(again.journal.mirrorSize()).toBe(0);
    await again.close();
    expect(await contents(f.store)).toEqual(await contents(h.primary));
  });

  test("a re-queued entity (crash before the caller's mark) is written once", async () => {
    const mirror = new MemoryStore(new MemoryChain(), WRITER);
    const h = harness(mirror);
    const rec = await h.start();
    note(rec, 1);
    await rec.flush();
    const before = await contents(mirror);
    const stored = await h.primary.get(rec.journal.batch(0n)?.entityKey as Hex, "afr.batch.v1");
    expect(stored).not.toBeNull();
    // re-queue what's already mirrored, as a crash-and-redo would
    rec.journal.enqueueMirror({
      schema: "afr.batch.v1",
      attrs: stored?.attrs as never,
      payload: stored?.payload as Uint8Array,
      expiresAt: { days: 30 },
      readonly: true,
      permissionlessExtension: true,
      lock: true,
      idempotencyKey: BATCH0_ID,
    });
    await rec.flush();
    expect(rec.journal.mirrorSize()).toBe(0);
    await rec.close();
    // batch 0 still has exactly one mirror copy (later flushes may add other batches)
    const hex = Buffer.from(stored?.payload as Uint8Array).toString("hex");
    expect(before["afr.batch.v1"]?.filter((p) => p === hex)).toHaveLength(1);
    expect((await contents(mirror))["afr.batch.v1"]?.filter((p) => p === hex)).toHaveLength(1);
  });

  test("a mirror holding other bytes under our id is refused (MIRROR_MISMATCH), not counted as copied", async () => {
    const { logged, logger } = capture();
    const mirror = new MemoryStore(new MemoryChain(), WRITER);
    // plant a different entity under batch 0's idempotency key, as a reused mirror DB would
    await mirror.await(
      await mirror.put({
        schema: "afr.batch.v1",
        attrs: {
          agent_key: AK,
          lane: 0n,
          seq_from: 0n,
          seq_to: 0n,
          chain_root: `0x${"01".repeat(32)}`,
          prev_chain_root: `0x${"00".repeat(32)}`,
          batch_root: `0x${"02".repeat(32)}`,
          session_key: WRITER,
          epoch_id: 0n,
          record_count: 1n,
          privacy: 0n,
        },
        payload: new Uint8Array(randomBytes(64)),
        expiresAt: { days: 1 },
        readonly: true,
        permissionlessExtension: true,
        lock: true,
        idempotencyKey: BATCH0_ID,
      }),
    );
    const h = harness(mirror, logger);
    const rec = await h.start();
    note(rec, 1);
    await rec.flush();
    expect(rec.journal.mirrorSize()).toBeGreaterThan(0);
    await rec.close();
    expect(logged.join()).toContain("MIRROR_MISMATCH");
  });

  test("config asks for a mirror but none is injected: logged, nothing queued", async () => {
    const { logged, logger } = capture();
    const h = harness(undefined, logger);
    const rec = await h.start();
    note(rec, 1);
    await rec.flush();
    expect(rec.journal.mirrorSize()).toBe(0);
    await rec.close();
    expect(logged.join()).toContain("MIRROR_UNCONFIGURED");
  });
  test("canary: plaintext never reaches the mirror (CLAUDE.md rule 2)", async () => {
    const canary = createCanary();
    const mirror = new MemoryStore(new MemoryChain(), WRITER);
    const h = harness(mirror);
    const rec = await h.start();
    rec.capture({
      type: "tool_call",
      tool: { server: "s", name: "t" },
      body: { args: canary.value },
    });
    await rec.flush();
    await rec.close();
    const payloads: string[] = [];
    for (const schema of SCHEMAS)
      for await (const e of mirror.query({ schema, where: { agent_key: { eq: AK } } }))
        payloads.push(
          Buffer.from(e.payload).toString("latin1"),
          JSON.stringify(e.attrs, (_k, v) => (typeof v === "bigint" ? `${v}` : v)),
        );
    expect(payloads.length).toBeGreaterThan(2);
    canary.assertAbsent(...payloads);
  });
});
