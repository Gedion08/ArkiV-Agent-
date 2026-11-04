// P2 definition of done, chaos: Arkiv 429 / timeout / lost response / revert injected at random (seeded)
// into every kind of write (delegation, profile, keygrant, batch), plus a crash mid-submit → zero
// duplicate entities and zero lost batches, and no plaintext in any attribute or payload of any entity.
// Single failures per kind are R8 in batcher.test.ts.
import { agentKey } from "@afr/core";
import { generateReaderKey, sealKeygrant } from "@afr/crypto";
import { createCanary } from "@afr/log";
import {
  type AfrSchemaName,
  type InjectedFailure,
  MemoryChain,
  MemoryStore,
  SCHEMA_NAMES,
  SCHEMA_SPEC,
  type StoredEntity,
} from "@afr/store";
import type { Hex } from "viem";
import { expect, test } from "vitest";
import { Recorder } from "../src/index.js";
import { AGENT, env, ready, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const KINDS: InjectedFailure[] = ["429", "timeout", "lost_response", "revert"];

/** mulberry32: a reproducible failure schedule per seed. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function entities<S extends AfrSchemaName>(store: MemoryStore, schema: S) {
  const out: StoredEntity<S>[] = [];
  // every schema queried here has an agent_key attr (checked by the caller)
  const where = { agent_key: { eq: AK } } as never;
  for await (const e of store.query({ schema, where })) out.push(e);
  return out;
}

for (const seed of [1, 7, 42]) {
  test(`chaos seed ${seed}: random 429/timeout/lost/revert + a crash → no duplicate, no lost batch`, async () => {
    const rand = rng(seed);
    const canary = createCanary();
    const reader = (await generateReaderKey()).pub;
    const config = tmpConfig({ encryption: { readers: [reader] } });
    const chain = new MemoryChain();
    const injected = { n: 0 };
    const newStore = () => new MemoryStore(chain, WRITER);
    const start = (store: MemoryStore) =>
      ready(
        Recorder.start({
          config,
          env,
          autoRotate: false,
          upload: { store, tickMs: 3_600_000, sealKeygrant },
        }),
      );
    // queued before a flush, so statements (delegation, profile, keygrant) get hit too, not only batches
    const chaos = (store: MemoryStore) => {
      const n = 1 + Math.floor(rand() * 3);
      for (let i = 0; i < n; i++) {
        store.failNext(KINDS[Math.floor(rand() * KINDS.length)] as InjectedFailure);
        injected.n++;
      }
    };

    let store = newStore();
    chaos(store);
    let rec = await start(store);
    let seq = 0;
    for (let round = 0; round < 12; round++) {
      for (let i = 0; i < 1 + Math.floor(rand() * 3); i++)
        rec.capture({
          type: "tool_call",
          tool: { server: "s", name: "t" },
          meta: { event: canary.value },
          body: { args: { seq: seq++, secret: canary.value }, result: canary.value },
        });
      chaos(store);
      await rec.flush();
      if (round === 6) {
        // crash: what's in flight is lost with the process; the journal and the chain survive
        store.failNext("lost_response");
        rec.capture({ type: "note", meta: { event: "pre-crash" }, body: { args: {} } });
        await rec.flush();
        await rec.delegationReady();
        rec.journal.close();
        store = newStore();
        rec = await start(store);
      }
    }
    // the outage ends: drain until every journaled batch is verified
    for (let i = 0; i < 20; i++) {
      if (Object.keys(rec.status().batches ?? {}).every((k) => k === "verified")) break;
      await rec.flush();
    }
    expect(Object.keys(rec.status().batches ?? {})).toEqual(["verified"]);
    await rec.close(); // its session_end may meet a leftover failure: journaled, not lost
    expect(injected.n).toBeGreaterThan(10);
    // the next process (no more failures) uploads whatever the last one left
    rec = await start(newStore());
    await rec.flush();
    expect(Object.keys(rec.status().batches ?? {})).toEqual(["verified"]);
    const end = rec.journal.tip().nextSeq; // this close() adds session_end here
    await rec.close();

    // zero duplicates: one entity per batch position, per session key, per (epoch, reader), one profile
    const batches = await entities(store, "afr.batch.v1");
    const froms = batches.map((b) => b.attrs.seq_from);
    expect(new Set(froms).size).toBe(froms.length);
    const sessionKeys = (await entities(store, "afr.delegation.v1")).map(
      (d) => (d.attrs as { session_key: Hex }).session_key,
    );
    expect(sessionKeys.length).toBeGreaterThanOrEqual(2); // one per process
    expect(new Set(sessionKeys).size).toBe(sessionKeys.length);
    const grants = (await entities(store, "afr.keygrant.v1")).map(
      (g) => `${g.attrs.epoch_id}:${g.attrs.reader}`,
    );
    expect(grants.length).toBeGreaterThan(0);
    expect(new Set(grants).size).toBe(grants.length);
    expect(await entities(store, "afr.agent.v1")).toHaveLength(1);

    // zero lost batches: the batches tile [0, last session_end]
    const sorted = [...batches].sort((a, b) => Number(a.attrs.seq_from - b.attrs.seq_from));
    let next = 0n;
    for (const b of sorted) {
      expect(b.attrs.seq_from).toBe(next);
      next = b.attrs.seq_to + 1n;
    }
    expect(next).toBe(end + 1n);

    // CLAUDE.md rule 2 over every entity written: no attribute or payload carries the plaintext
    const exposed: string[] = [];
    for (const schema of SCHEMA_NAMES) {
      if (!("agent_key" in SCHEMA_SPEC[schema].attrs)) continue;
      for (const e of await entities(store, schema))
        exposed.push(
          JSON.stringify(e.attrs, (_k, v) => (typeof v === "bigint" ? `${v}` : v)),
          Buffer.from(e.payload).toString("latin1"),
        );
    }
    expect(exposed.length).toBeGreaterThan(10);
    canary.assertAbsent(...exposed);
  }, 60_000);
}
