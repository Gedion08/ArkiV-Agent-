// P2-10: batcher + uploader (L2 §4, §9). R7 frame size property, R8 write state machine.
import { randomBytes } from "node:crypto";
import { agentKey, batchDigest, LIMITS, type RecordBodyV1, recoverRecordSigner } from "@afr/core";
import { decryptBatch } from "@afr/crypto";
import { createCanary, type Logger } from "@afr/log";
import {
  decodeBody,
  decodeFrame,
  type InjectedFailure,
  MemoryChain,
  MemoryStore,
  unpackPlaintext,
} from "@afr/store";
import { type Hex, hexToBytes } from "viem";
import { describe, expect, test } from "vitest";
import { Recorder, type UploadOptions } from "../src/index.js";
import { AGENT, env, ready, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;

function harness(over: Record<string, unknown> = {}, upload: Partial<UploadOptions> = {}) {
  const config = tmpConfig(over);
  const chain = new MemoryChain();
  const store = new MemoryStore(chain, WRITER, config.agent.privacy_level);
  const start = (s: MemoryStore = store) =>
    ready(
      Recorder.start({
        config,
        env,
        autoRotate: false,
        upload: { store: s, tickMs: 3_600_000, ...upload },
      }),
    );
  return { config, chain, store, start };
}

async function stored(store: MemoryStore) {
  const out = [];
  for await (const e of store.query({
    schema: "afr.batch.v1",
    where: { agent_key: { eq: AK } },
    orderBy: { attr: "seq_from", dir: "asc" },
  }))
    out.push(e);
  return out;
}

/** Decrypts one stored frame and checks it against the journal; returns its public section. */
async function checkFrame(rec: Recorder, frame: Uint8Array) {
  expect(frame.length).toBeLessThanOrEqual(LIMITS.BATCH_MAX_FRAME_BYTES);
  const { pub, ct } = decodeFrame(frame);
  const ctx = {
    agentKey: AK,
    lane: pub.lane,
    seqFrom: BigInt(pub.seq_from),
    seqTo: BigInt(pub.seq_to),
    batchRoot: pub.batch_root as Hex,
  };
  const digest = batchDigest({
    ...ctx,
    prevChainRoot: pub.prev_chain_root as Hex,
    chainRoot: pub.chain_root as Hex,
    payloadCtHash: pub.payload_ct_hash as Hex,
  });
  expect(pub.session_keys).toContain(await recoverRecordSigner(digest, pub.batch_sig as Hex));
  const plain = decryptBatch(
    {
      ct,
      iv: hexToBytes(pub.iv as Hex),
      wrappedDek: hexToBytes(pub.wrapped_dek as Hex),
      epochId: pub.epoch_id,
      kekId: pub.kek_id as Hex,
    },
    ctx,
    rec.journal.epochKek(pub.epoch_id),
  );
  const { headers, bodies } = unpackPlaintext(plain);
  const journaled = rec.journal.range(ctx.seqFrom, ctx.seqTo);
  expect(headers).toEqual(journaled.map((r) => r.headerJcs));
  expect(pub.records.map((r) => r.hash)).toEqual(journaled.map((r) => r.hash));
  bodies.forEach((b, i) => {
    const body = decodeBody(b);
    const full = rec.journal.readBody((journaled[i] as { seq: bigint }).seq);
    // a record truncated harder to fit the frame keeps its salt; otherwise bodies are identical
    if (body.truncated?.length !== full.truncated?.length) expect(body.salt).toBe(full.salt);
    else expect(body).toEqual(full as RecordBodyV1);
  });
  return pub;
}

const hex = (n: number) => randomBytes(n).toString("hex");

describe("P2-10 batcher + uploader", () => {
  test("R7: fuzzed record sizes never produce a frame > 120 KiB; frames chain and decrypt", async () => {
    const h = harness({ capture: { max_body_bytes: LIMITS.BATCH_TARGET_BYTES } });
    const rec = await h.start();
    let seed = 7;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    for (let round = 0; round < 6; round++) {
      for (let i = 0; i < 40; i++) {
        const size = Math.floor(rnd() ** 3 * 100 * 1024); // mostly small, some ≈ 100 KiB
        const text = rnd() < 0.5 ? hex(size >> 1) : "a".repeat(size); // incompressible or not
        rec.capture({
          type: "tool_call",
          tool: { server: "s", name: "t" },
          body: { args: { text, n: -1.5, none: null } },
        });
      }
      await rec.flush();
    }
    await rec.close();
    const reopened = await h.start(); // for journal access (adds its own session batch)
    await reopened.flush();
    let prev = `0x${"00".repeat(32)}`;
    let next = 0n;
    const entities = await stored(h.store);
    for (const e of entities) {
      const pub = await checkFrame(reopened, e.payload);
      expect(pub.prev_chain_root).toBe(prev);
      expect(BigInt(pub.seq_from)).toBe(next);
      prev = pub.chain_root;
      next = BigInt(pub.seq_to) + 1n;
    }
    expect(next).toBe(reopened.journal.batchTip().nextSeq);
    expect(entities.length).toBeGreaterThan(7); // size triggers split the rounds
    await reopened.close();
  }, 60_000);

  test("batch attrs and privacy 1 flags; privacy 0 omits flags", async () => {
    const h = harness({ agent: { id: AGENT, privacy_level: 1 } }, { approvalThresholdCents: 100n });
    const rec = await h.start();
    rec.capture({
      type: "tx_sign",
      tx: {
        chain_id: 8453n,
        from: `0x${"11".repeat(20)}` as Hex,
        to: `0x${"22".repeat(20)}` as Hex,
        nonce: 3n,
        value: 1n,
        value_usd_cents: 500n,
      },
      body: { calldata: "0x" },
    });
    await rec.flush();
    const [e] = await stored(h.store);
    expect(e?.attrs).toMatchObject({
      agent_key: AK,
      lane: 0n,
      seq_from: 0n,
      seq_to: 1n,
      record_count: 2n,
      privacy: 1n,
      has_tx: true,
      has_block: false,
      has_unapproved_tx: true,
      has_violation: false,
    });
    expect(e?.meta).toMatchObject({ readonly: true, permissionlessExtension: true });
    await rec.close();

    const h0 = harness();
    const r0 = await h0.start();
    await r0.flush();
    const [e0] = await stored(h0.store);
    expect(e0?.attrs).not.toHaveProperty("has_tx");
    expect(decodeFrame(e0?.payload as Uint8Array).pub.flags).toBeUndefined();
    await r0.close();
  });

  test("R8: lost response / timeout / revert / 429 → one entity per batch, never re-signed", async () => {
    for (const kind of ["lost_response", "timeout", "revert", "429"] as InjectedFailure[]) {
      const gate = { open: false }; // hold the batch so the failure hits it, not a statement
      const h = harness({}, { canSubmit: () => gate.open });
      const rec = await h.start();
      await rec.flush(); // delegation + profile only
      gate.open = true;
      h.store.failNext(kind);
      await rec.flush(); // the first attempt hits the failure and stops ("waiting")
      await rec.flush(); // reconcile / re-prepare / retry
      expect({ kind, batches: rec.status().batches }).toEqual({ kind, batches: { verified: 1 } });
      const all = await stored(h.store);
      expect(all).toHaveLength(1);
      const row = rec.journal.batch(0n);
      expect(row?.entityKey).toBe(all[0]?.ref.key);
      expect(row?.attempts).toBe(kind === "revert" ? 1 : 0); // only a proven revert re-prepares
      await rec.close();
      expect((await stored(h.store)).map((e) => e.attrs.seq_from)).toEqual([0n, 1n]);
    }
  });

  test("crash while submitting: restart reconciles from the journal, idempotent re-put, no duplicate", async () => {
    const gate = { open: false };
    const h = harness({}, { canSubmit: () => gate.open });
    const rec = await h.start();
    await rec.flush(); // delegation + profile only
    gate.open = true;
    h.store.failNext("lost_response");
    await rec.flush();
    expect(rec.status().batches).toEqual({ submitting: 1 });
    await rec.delegationReady(); // else the late delegation write hits the closed journal
    rec.journal.close(); // crash: the in-memory PendingWrite is lost
    const fresh = new MemoryStore(h.chain, WRITER); // a new process' store knows no pending writes
    const again = await h.start(fresh);
    await again.flush();
    await again.flush();
    const batches = again.status().batches ?? {};
    expect(Object.keys(batches)).toEqual(["verified"]);
    const seqs = (await stored(fresh)).map((e) => e.attrs.seq_from);
    expect(seqs).toHaveLength(batches.verified as number);
    expect(new Set(seqs).size).toBe(seqs.length); // one entity per seq_from
    await again.close();
  });

  test("close triggers: record count and age; uploads keep seq order", async () => {
    let now = 1_800_000_000_000;
    const store = new MemoryStore(new MemoryChain(), WRITER);
    const rec = await ready(
      Recorder.start({
        config: tmpConfig({ batch: { max_age_ms: 5_000 } }),
        env,
        autoRotate: false,
        now: () => now,
        upload: { store, tickMs: 3_600_000 },
      }),
    );
    await rec.flush(); // session_start
    for (let i = 0; i < LIMITS.MAX_RECORDS_PER_BATCH; i++)
      rec.capture({ type: "note", body: { args: { i } } });
    await new Promise((r) => setImmediate(r)); // the count trigger queued a flush
    await rec.flush(false);
    expect(rec.journal.batchTip().nextSeq).toBe(1001n);
    rec.capture({ type: "note", body: { args: { late: true } } });
    await rec.flush(false);
    expect(rec.journal.batchTip().nextSeq).toBe(1001n); // not due yet
    now += 5_000;
    await rec.flush(false);
    expect(rec.journal.batchTip().nextSeq).toBe(1002n);
    const seqs = (await stored(store)).map((e) => e.attrs.seq_from);
    expect(seqs).toEqual([...seqs].sort((a, b) => (a < b ? -1 : 1)));
    await rec.close();
  }, 20_000); // 1,000 captures + seal; slow under the parallel suite

  test("records of a dead session key are batched with the next signable record", async () => {
    const h = harness();
    const first = await Recorder.start({ config: h.config, env, autoRotate: false }); // journal only
    first.capture({ type: "note", body: { args: { before: "crash" } } });
    await first.delegationReady(); // else the late delegation write hits the closed journal
    first.journal.close(); // crash: no session_end, its session key is gone
    const rec = await h.start();
    await rec.flush();
    const [e] = await stored(h.store);
    const pub = decodeFrame(e?.payload as Uint8Array).pub;
    expect(pub.session_keys).toHaveLength(2); // old key's records + the new session_start
    expect(pub.records.at(-1)?.sk).toBe(1);
    await rec.close();
  });

  test("ADR-024: a dead-key backlog too big for one frame splits; parts are signed by the current key", async () => {
    const h = harness({ capture: { max_body_bytes: LIMITS.BATCH_TARGET_BYTES } });
    const first = await Recorder.start({ config: h.config, env, autoRotate: false });
    for (let i = 0; i < 8; i++)
      first.capture({ type: "note", body: { args: { text: hex(30_000) } } });
    await first.delegationReady();
    first.journal.close(); // crash: the old session key is gone
    const rec = await h.start();
    await rec.flush();
    const current = rec.status().sessionKey.toLowerCase();
    const pubs = [];
    for (const e of await stored(h.store)) pubs.push(await checkFrame(rec, e.payload));
    expect(pubs.length).toBeGreaterThan(1);
    for (const pub of pubs.slice(0, -1)) {
      expect(pub.session_keys.at(-1)).toBe(current); // listed only to sign the batch
      expect(pub.records.every((r) => pub.session_keys[r.sk] !== current)).toBe(true);
    }
    expect(rec.status().batches).toEqual({ verified: pubs.length });
    await rec.close();
  }, 30_000);

  test("canary: plaintext never reaches the uploaded frame, entity attrs or logs (CLAUDE.md rule 2)", async () => {
    const canary = createCanary();
    const logged: string[] = [];
    const log = (o: unknown, m?: string) => logged.push(JSON.stringify([o, m]));
    const logger = {
      warn: log,
      error: log,
      info: log,
      debug: log,
      trace: log,
    } as unknown as Logger;
    const store = new MemoryStore(new MemoryChain(), WRITER, 1);
    const rec = await ready(
      Recorder.start({
        config: tmpConfig({ agent: { id: AGENT, privacy_level: 1 } }),
        env,
        autoRotate: false,
        logger,
        upload: { store, tickMs: 3_600_000 },
      }),
    );
    rec.capture({
      type: "tool_call",
      tool: { server: "s", name: "t" },
      body: { args: canary.value },
    });
    store.failNext("revert"); // exercise the warn paths too
    await rec.flush();
    await rec.flush();
    await rec.close();
    const entities = await stored(store);
    expect(entities.length).toBeGreaterThan(0);
    const all = [...store.chain.rows.values()]; // batches + delegation + agent profile
    expect(all.map((r) => r.schema)).toContain("afr.delegation.v1");
    canary.assertAbsent(
      ...all.map((e) => Buffer.from(e.payload).toString("latin1")),
      ...all.map((e) => JSON.stringify(e.attrs, (_, v) => (typeof v === "bigint" ? `${v}` : v))),
      ...logged,
    );
    expect(logged.length).toBeGreaterThan(0);
  });
});
