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
   * Seals every unbatched record (ADR-024: a batch whose record keys are all gone is signed by the
   * current session key). Persists them as `sealed`.
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
      const ready: SealRecord[] = recs.slice(0, max).map((r) => ({
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
   * rarely need sealBatches' split fallback.
   */
  *#chunks(records: SealRecord[]): Generator<SealRecord[]> {
    const target = this.#o.targetBytes ?? LIMITS.BATCH_TARGET_BYTES;
    let start = 0;
    let size = 0;
    for (let i = 0; i < records.length; i++) {
      const r = records[i] as SealRecord;
      const bytes = r.headerJcs.length + JSON.stringify(r.body).length + PUB_BYTES_PER_RECORD;
      if (size + bytes > target && i > start) {
        yield records.slice(start, i);
        size = 0;
        start = i;
      }
      size += bytes;
    }
    if (start < records.length) yield records.slice(start);
  }
}
