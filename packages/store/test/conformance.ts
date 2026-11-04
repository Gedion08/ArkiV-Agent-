// L3 §11 conformance suite C1–C10. Every EvidenceStore implementation runs it (memory + Postgres in
// CI, Arkiv nightly with ARKIV_E2E=1).
import { EVIDENCE_LOCK_ADDRESS } from "@afr/core";
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";
import {
  type AttrsOf,
  type EvidenceStore,
  type Expiry,
  listBatches,
  type PutRequest,
  type StoredEntity,
} from "../src/index.js";

export interface ConformanceStore extends EvidenceStore {
  /** Owner-side patch/delete attempts (AFR never does this; the cases prove it can't succeed). */
  patch(key: Hex, attrs: Record<string, unknown>): Promise<void>;
  delete(key: Hex): Promise<void>;
}

export interface Harness {
  /** Writer A (privacy level 0) and, if available, writer B on the same backing store. */
  a: ConformanceStore;
  b?: ConformanceStore;
  writerA: Hex;
  /** C10: a short expiry and how to get past it (simulated clock, or real waiting on Arkiv). */
  expiry: { expiresAt: Expiry; wait(): Promise<void> };
  /** C5 entity count (250 by default; smaller on a paid network). */
  c5Count?: number;
  /** Failure injection (memory) or undefined where the impl can't inject. */
  failNext?: (kind: "timeout" | "revert" | "lost_response" | "429") => void;
}

let n = 0;
// unique per run, so repeated runs on a persistent store (Arkiv) don't see each other's entities
const RUN = BigInt(Date.now()) << 80n;
const hex32 = (x: number | bigint) => `0x${BigInt(x).toString(16).padStart(64, "0")}` as Hex;

export function batchReq(
  over: Omit<Partial<PutRequest<"afr.batch.v1">>, "attrs"> & {
    attrs?: Partial<AttrsOf<"afr.batch.v1">>;
  } = {},
): PutRequest<"afr.batch.v1"> {
  const id = ++n;
  const { attrs, ...rest } = over;
  return {
    schema: "afr.batch.v1",
    attrs: {
      agent_key: hex32(RUN + 0xa9e47n),
      lane: 0n,
      seq_from: BigInt(id * 10),
      seq_to: BigInt(id * 10 + 9),
      chain_root: hex32(id),
      prev_chain_root: hex32(id - 1),
      batch_root: hex32(1_000_000 + id),
      session_key: `0x${"d4".repeat(20)}`,
      epoch_id: 352n,
      record_count: 10n,
      privacy: 0n,
      ...attrs,
    },
    payload: new TextEncoder().encode(`frame-${id}`),
    expiresAt: { days: 30 },
    readonly: true,
    permissionlessExtension: true,
    lock: true,
    idempotencyKey: hex32(RUN + BigInt(2_000_000 + id)),
    ...rest,
  };
}

const codeOf = async (p: Promise<unknown>) =>
  p.then(
    () => "NO_ERROR",
    (e: { code?: string }) => e.code ?? "UNTYPED",
  );
async function collect<T>(it: AsyncIterable<T>) {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
}
async function putAwait(s: EvidenceStore, req: PutRequest) {
  return s.await(await s.put(req));
}

export function conformance(name: string, make: () => Promise<Harness>) {
  describe(`L3 §11 conformance: ${name}`, () => {
    test("C1 put → await → get returns identical payload, attrs and flags", async () => {
      const h = await make();
      const req = batchReq({ attrs: { privacy: 0n } });
      const ref = await putAwait(h.a, req);
      const e = (await h.a.get(ref.key, "afr.batch.v1")) as StoredEntity<"afr.batch.v1">;
      expect(e.payload).toEqual(req.payload);
      expect(e.attrs).toEqual(req.attrs);
      expect(e.meta).toMatchObject({ readonly: true, permissionlessExtension: true });
      expect(e.meta.creator.toLowerCase()).toBe(h.writerA.toLowerCase());
    });

    test("C2 readonly: patch attempt fails", async () => {
      const h = await make();
      const ref = await putAwait(h.a, batchReq({ lock: false }));
      expect(await codeOf(h.a.patch(ref.key, { record_count: 11n }))).toBe("READONLY");
    });

    test("C3 lock: owner = lock address; delete attempt by the writer fails", async () => {
      const h = await make();
      const ref = await putAwait(h.a, batchReq());
      const e = await h.a.get(ref.key, "afr.batch.v1");
      expect(e?.meta.owner.toLowerCase()).toBe(EVIDENCE_LOCK_ADDRESS.toLowerCase());
      expect(await codeOf(h.a.delete(ref.key))).toBe("NOT_OWNER");
      expect(await codeOf(h.a.patch(ref.key, { record_count: 11n }))).toBe("NOT_OWNER");
      expect(await h.a.get(ref.key, "afr.batch.v1")).not.toBeNull();
    });

    test("C4 permissionless extension by another account succeeds; shortening fails; flag required", async () => {
      const h = await make();
      const ref = await putAwait(h.a, batchReq({ expiresAt: { days: 2 } }));
      const before = (await h.a.get(ref.key, "afr.batch.v1"))?.meta.expiresAtBlock as bigint;
      // without B, A itself is "a different account": after the lock it no longer owns the entity
      const other = h.b ?? h.a;
      await other.extend(ref.key, { days: 10 });
      const after = (await h.a.get(ref.key, "afr.batch.v1"))?.meta.expiresAtBlock as bigint;
      expect(after).toBeGreaterThan(before);
      expect(await codeOf(other.extend(ref.key, { days: 1 }))).toBe("EXPIRY_NOT_EXTENDED");
      const noFlag = await putAwait(h.a, batchReq({ permissionlessExtension: false }));
      expect(await codeOf(other.extend(noFlag.key, { days: 60 }))).toBe("NOT_OWNER");
    });

    test("C5 keyset query over 250 entities (c5Count on paid networks) returns all, in order, no duplicates", async () => {
      const h = await make();
      const agent = hex32(RUN + 0xc5n);
      const count = h.c5Count ?? 250;
      for (let i = 0; i < count; i++)
        await putAwait(
          h.a,
          batchReq({
            attrs: { agent_key: agent, seq_from: BigInt(i * 10), seq_to: BigInt(i * 10 + 9) },
          }),
        );
      const pin = (await h.a.head()).block;
      const got = await collect(
        h.a.query({
          schema: "afr.batch.v1",
          where: { agent_key: { eq: agent }, lane: { eq: 0n }, seq_from: { gte: 0n } },
          createdBy: [h.writerA],
          orderBy: { attr: "seq_from", dir: "asc" },
          pageSize: 100,
          atBlock: pin,
        }),
      );
      expect(got).toHaveLength(count);
      expect(new Set(got.map((e) => e.ref.key)).size).toBe(count);
      expect(got.map((e) => e.attrs.seq_from)).toEqual(
        Array.from({ length: count }, (_, i) => BigInt(i * 10)),
      );
      // P2-09: keyset listBatches (small pages exercise the cut + eq path) sees the same entities
      const listed = await collect(
        listBatches(h.a, { agentKey: agent, lane: 0n, writers: [h.writerA], pageSize: 7 }),
      );
      expect(listed.map((e) => e.ref.key)).toEqual(got.map((e) => e.ref.key));
    });

    test("C6 createdBy excludes entities from other writers", async () => {
      const h = await make();
      const agent = hex32(RUN + 0xc6n);
      await putAwait(h.a, batchReq({ attrs: { agent_key: agent } }));
      if (h.b) await putAwait(h.b, batchReq({ attrs: { agent_key: agent } }));
      const q = (createdBy?: Hex[]) =>
        collect(
          h.a.query({
            schema: "afr.batch.v1",
            where: { agent_key: { eq: agent } },
            ...(createdBy ? { createdBy } : {}),
          }),
        );
      expect(await q([h.writerA])).toHaveLength(1);
      expect(await q([`0x${"0e".repeat(20)}`])).toHaveLength(0);
      expect(await q()).toHaveLength(h.b ? 2 : 1);
    });

    test("C7 120 KiB frame accepted; larger rejected client-side before sending", async () => {
      const h = await make();
      await putAwait(h.a, batchReq({ payload: new Uint8Array(120 * 1024).fill(7) }));
      const big = batchReq({ payload: new Uint8Array(120 * 1024 + 1) });
      expect(await codeOf(h.a.put(big))).toBe("PAYLOAD_TOO_LARGE");
      expect(await h.a.reconcile({ store: h.a.kind, idempotencyKey: big.idempotencyKey })).toEqual({
        state: "not_sent",
      });
    });

    test("C8 reconcile after an injected lost response → confirmed, no duplicate entity", async (ctx) => {
      const h = await make();
      if (!h.failNext) return ctx.skip();
      const agent = hex32(RUN + 0xc8n);
      const req = batchReq({ attrs: { agent_key: agent } });
      h.failNext("lost_response");
      const w = await h.a.put(req);
      expect(await codeOf(h.a.await(w))).toBe("LOST_RESPONSE");
      const r = await h.a.reconcile(w);
      expect(r.state).toBe("confirmed");
      const again = await h.a.await(await h.a.put(req)); // idempotent re-put
      expect(r.state === "confirmed" && again.key).toBe(r.state === "confirmed" && r.ref.key);
      const all = await collect(
        h.a.query({ schema: "afr.batch.v1", where: { agent_key: { eq: agent } } }),
      );
      expect(all).toHaveLength(1);
      // a reverted write reconciles as reverted and leaves nothing behind
      const rev = batchReq({ attrs: { agent_key: agent } });
      h.failNext("revert");
      const wr = await h.a.put(rev);
      expect(await codeOf(h.a.await(wr))).toBe("REVERTED");
      expect((await h.a.reconcile(wr)).state).toBe("reverted");
      expect(
        await collect(h.a.query({ schema: "afr.batch.v1", where: { agent_key: { eq: agent } } })),
      ).toHaveLength(1);
    });

    test("C9 privacy-level attribute allowlist enforced", async () => {
      const h = await make();
      expect(await codeOf(h.a.put(batchReq({ attrs: { has_tx: true } })))).toBe("PRIVACY_ATTR");
      expect(await codeOf(h.a.put(batchReq({ attrs: { privacy: 1n } })))).toBe("PRIVACY_ATTR");
    });

    test("C10 expiry: entity not returned after expiry", async () => {
      const h = await make();
      const agent = hex32(RUN + 0xc10n);
      const ref = await putAwait(
        h.a,
        batchReq({ attrs: { agent_key: agent }, expiresAt: h.expiry.expiresAt }),
      );
      await h.expiry.wait();
      expect(await h.a.get(ref.key, "afr.batch.v1")).toBeNull();
      expect(
        await collect(h.a.query({ schema: "afr.batch.v1", where: { agent_key: { eq: agent } } })),
      ).toHaveLength(0);
      expect(await codeOf((h.b ?? h.a).extend(ref.key, { days: 5 }))).toBe("NOT_FOUND");
    });
  });
}
