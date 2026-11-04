// L3 §8 reading: keyset pagination over afr.batch.v1 by seq_from, plus duplicate grouping for the
// equivocation check (L7 step 3). Data read here is untrusted: callers verify signatures (L7).
import type { Hex } from "viem";
import type { EvidenceStore, StoredEntity } from "./types.js";

export type BatchEntity = StoredEntity<"afr.batch.v1">;

export interface ListBatchesOptions {
  agentKey: Hex;
  lane: bigint;
  fromSeq?: bigint;
  /** Discovery filter only (agent profile writers); omit for --no-writer-filter. */
  writers?: Hex[];
  /** ≤ 100. */
  pageSize?: number;
}

/**
 * Every batch entity of (agentKey, lane) with seq_from ≥ fromSeq, ascending by seq_from, each once.
 * Duplicates sharing a seq_from are all yielded, even across a page boundary or when there are more
 * than a page of them (spam can't stall or hide a fork): a full page is cut at its last seq_from,
 * which is then read exhaustively with an `eq` query.
 */
export async function* listBatches(
  store: EvidenceStore,
  o: ListBatchesOptions,
): AsyncIterable<BatchEntity> {
  const pageSize = o.pageSize ?? 100;
  const atBlock = (await store.head()).block;
  const seen = new Set<Hex>();
  const query = (seqFrom: { gte: bigint } | { eq: bigint }) =>
    store.query({
      schema: "afr.batch.v1",
      where: { agent_key: { eq: o.agentKey }, lane: { eq: o.lane }, seq_from: seqFrom },
      ...(o.writers ? { createdBy: o.writers } : {}),
      orderBy: { attr: "seq_from", dir: "asc" },
      pageSize,
      atBlock,
    });
  const fresh = (b: BatchEntity) => !seen.has(b.ref.key) && !!seen.add(b.ref.key);
  let next = o.fromSeq ?? 0n;
  while (true) {
    const page: BatchEntity[] = [];
    for await (const b of query({ gte: next })) {
      page.push(b);
      if (page.length === pageSize) break;
    }
    if (page.length < pageSize) {
      for (const b of page) if (fresh(b)) yield b;
      return;
    }
    const cut = (page[page.length - 1] as BatchEntity).attrs.seq_from;
    for (const b of page) if (b.attrs.seq_from < cut && fresh(b)) yield b;
    for await (const b of query({ eq: cut })) if (fresh(b)) yield b;
    next = cut + 1n;
  }
}

export interface Equivocation {
  code: "EQUIVOCATION";
  lane: bigint;
  seqFrom: bigint;
  /** Keys of the valid but differing batches claiming this seq_from. */
  keys: Hex[];
}

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Groups batches by (lane, seq_from), keeps only those `isValid` accepts (batch_sig under a valid
 * delegation, L7), and reports every group whose valid members are not byte-identical. Identical
 * duplicates (rollback re-creates) collapse to one. Returns the first valid batch per seq_from, in
 * input order, and the equivocations.
 */
export async function groupDuplicates(
  batches: Iterable<BatchEntity> | AsyncIterable<BatchEntity>,
  isValid: (b: BatchEntity) => boolean | Promise<boolean>,
): Promise<{ batches: BatchEntity[]; equivocations: Equivocation[] }> {
  const groups = new Map<string, BatchEntity[]>();
  const kept: BatchEntity[] = [];
  for await (const b of batches) {
    if (!(await isValid(b))) continue;
    const id = `${b.attrs.lane}:${b.attrs.seq_from}`;
    const g = groups.get(id);
    if (!g) {
      groups.set(id, [b]);
      kept.push(b);
    } else if (!g.some((x) => sameBytes(x.payload, b.payload))) g.push(b);
  }
  const equivocations: Equivocation[] = [];
  for (const g of groups.values()) {
    const first = g[0] as BatchEntity;
    if (g.length > 1)
      equivocations.push({
        code: "EQUIVOCATION",
        lane: first.attrs.lane,
        seqFrom: first.attrs.seq_from,
        keys: g.map((b) => b.ref.key),
      });
  }
  return { batches: kept, equivocations };
}
