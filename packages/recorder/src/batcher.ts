// Batcher (L2 §9): close triggers + sealing of journaled records into `sealed` batches (L2 §4).
// Restart-safe: unbatched records are whatever follows the last batch in the journal.
import { LIMITS } from "@afr/core";
import type { EpochKek } from "@afr/crypto";
import type { Logger } from "@afr/log";
import type { Journal } from "./journal.js";
import { type SealContext, type SealedBatch, type SealRecord, sealBatches } from "./seal.js";

/** Per-record public-section bytes (seq, hash, sig, sk in CBOR), not compressed. */
const PUB_BYTES_PER_RECORD = 230;

export interface BatcherOptions {
  journal: Journal;
  seal: Omit<SealContext, "kek"> & { kek: () => EpochKek };
  maxAgeMs?: number;
  targetBytes?: number;
  maxRecords?: number;
  now?: () => number;
  logger?: Logger;
}

export class Batcher {
  readonly #o: BatcherOptions;
  readonly #now: () => number;
  #count: number;
  #bytes = 0;
  #oldest: number | undefined;

  constructor(o: BatcherOptions) {
    this.#o = o;
    this.#now = o.now ?? Date.now;
    this.#count = Number(o.journal.tip().nextSeq - o.journal.batchTip().nextSeq);
    if (this.#count > 0) this.#oldest = this.#now();
  }

  get pendingRecords(): number {
    return this.#count;
  }

  /** Hot path: account for one journaled record. Returns whether a close trigger fired. */
  noteRecord(headerBytes: number, bodyBytes: number): boolean {
    this.#count++;
    this.#bytes += headerBytes + bodyBytes + PUB_BYTES_PER_RECORD;
    this.#oldest ??= this.#now();
    return this.due();
  }

  /** age ≥ max_age_ms, estimated size ≥ target_bytes, or count ≥ 1000. */
  due(): boolean {
    if (this.#count === 0 || this.#oldest === undefined) return false;
    return (
      this.#count >= (this.#o.maxRecords ?? LIMITS.MAX_RECORDS_PER_BATCH) ||
      this.#bytes >= (this.#o.targetBytes ?? LIMITS.BATCH_TARGET_BYTES) ||
      this.#now() - this.#oldest >= (this.#o.maxAgeMs ?? LIMITS.BATCH_MAX_AGE_MS)
    );
  }

  /**
   * Seals every unbatched record up to the last one whose session key is still held (a later
   * record, e.g. the next session_start, makes the rest signable). Persists them as `sealed`.
   */
  seal(): SealedBatch[] {
    const { journal, seal } = this.#o;
    const max = this.#o.maxRecords ?? LIMITS.MAX_RECORDS_PER_BATCH;
    const out: SealedBatch[] = [];
    for (;;) {
      const tip = journal.batchTip();
      const end = journal.tip().nextSeq - 1n;
      if (end < tip.nextSeq) break;
      const recs = journal.range(tip.nextSeq, end);
      let last = -1;
      for (let i = 0; i < recs.length; i++) {
        if (i >= max && last >= 0) break;
        if (seal.signerFor((recs[i] as (typeof recs)[number]).sessionKey)) last = i;
      }
      if (last < 0) break;
      const ready: SealRecord[] = recs.slice(0, last + 1).map((r) => ({
        ...r,
        body: journal.readBody(r.seq),
      }));
      const ctx = { ...seal, kek: seal.kek() };
      const sealed: SealedBatch[] = [];
      let prev = tip.chainRoot;
      for (const chunk of this.#chunks(ready)) {
        const out = sealBatches(chunk, prev, ctx, (code) =>
          this.#o.logger?.warn({ code }, "batch frame adjusted to fit"),
        );
        prev = (out.at(-1) as SealedBatch).pub.chain_root as `0x${string}`;
        sealed.push(...out);
      }
      journal.insertBatches(
        sealed.map((b) => ({
          seqFrom: b.seqFrom,
          seqTo: b.seqTo,
          frame: b.frame,
          batchRoot: b.pub.batch_root as `0x${string}`,
          prevChainRoot: b.pub.prev_chain_root as `0x${string}`,
          chainRoot: b.pub.chain_root as `0x${string}`,
        })),
      );
      out.push(...sealed);
    }
    this.#count = Number(journal.tip().nextSeq - journal.batchTip().nextSeq);
    this.#bytes = 0;
    this.#oldest = this.#count > 0 ? this.#now() : undefined;
    return out;
  }

  /**
   * Greedy pre-split by estimated size (uncompressed header + body + public overhead) so frames
   * rarely need sealBatches' split fallback; each chunk ends on a record whose key is still held.
   */
  *#chunks(records: SealRecord[]): Generator<SealRecord[]> {
    const target = this.#o.targetBytes ?? LIMITS.BATCH_TARGET_BYTES;
    let start = 0;
    let size = 0;
    let cut = -1; // last signable index in the current chunk
    for (let i = 0; i < records.length; i++) {
      const r = records[i] as SealRecord;
      const bytes = r.headerJcs.length + JSON.stringify(r.body).length + PUB_BYTES_PER_RECORD;
      if (size + bytes > target && cut >= start) {
        yield records.slice(start, cut + 1);
        size = 0;
        for (let j = cut + 1; j < i; j++) {
          const q = records[j] as SealRecord;
          size += q.headerJcs.length + JSON.stringify(q.body).length + PUB_BYTES_PER_RECORD;
        }
        start = cut + 1;
      }
      size += bytes;
      if (this.#o.seal.signerFor(r.sessionKey)) cut = i;
    }
    if (start < records.length) yield records.slice(start);
  }
}
