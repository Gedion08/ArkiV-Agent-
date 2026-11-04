// Uploader (L2 §4 batch state machine, §9 ordering) over an injected EvidenceStore.
//   sealed → prepared → submitting → (receipt_confirmed →) verified;  submitting → failed → prepared.
// Strictly one batch at a time in seq order: batch N+1 is submitted only once N is verified, so
// chain-root and writer-nonce order hold. A write is never re-signed: anything uncertain reconciles.
import { AfrError, type BatchPublicV1, batchId } from "@afr/core";
import type { Logger } from "@afr/log";
import {
  decodeFrame,
  type EvidenceStore,
  type Expiry,
  type PendingWrite,
  type PutRequest,
} from "@afr/store";
import { encodeAbiParameters, type Hex, keccak256 } from "viem";
import type { BatchRow, Journal } from "./journal.js";

export interface UploaderOptions {
  journal: Journal;
  store: EvidenceStore;
  agentKey: Hex;
  lane: number;
  privacy: 0 | 1 | 2;
  /** Rolling (default): 30-day creates, extended later; upfront: the retention (≤ 30 d). */
  expiresAt: Expiry;
  /** Submission gate: keygrants of the batch's epoch (L4 §5) and delegations (L2 §9, P2-12) first. */
  canSubmit?: (pub: BatchPublicV1) => boolean | Promise<boolean>;
  /** Runs in the same journal transaction that marks the batch verified (L2 §10 checkpoint, L3 §9 mirror). */
  onVerified?: (b: BatchRow, entityKey: Hex, req: PutRequest<"afr.batch.v1">) => void;
  logger?: Logger;
}

export type StepResult = "idle" | "progress" | "waiting";

/** Codes a store raises before anything was signed: safe to retry the same prepared write. */
const NOT_SENT = new Set(["RATE_LIMITED", "PAYLOAD_TOO_LARGE", "EXPIRY_INVALID", "CLOSED"]);

export class Uploader {
  readonly #o: UploaderOptions;
  /** PendingWrites returned by put() in this process (lost on restart → reconcile). */
  readonly #pending = new Map<bigint, PendingWrite>();

  constructor(o: UploaderOptions) {
    this.#o = o;
  }

  /** Idempotency key per (batch, attempt): a re-prepare after a proven revert is a new write. */
  #idempotencyKey(b: BatchRow): Hex {
    return keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "uint32" }],
        [batchId(this.#o.agentKey, this.#o.lane, b.seqFrom), b.attempts],
      ),
    );
  }

  #write(b: BatchRow): PendingWrite {
    return (
      this.#pending.get(b.seqFrom) ?? {
        store: this.#o.store.kind,
        idempotencyKey: this.#idempotencyKey(b),
        ...(b.predictedKey ? { predictedKey: b.predictedKey } : {}),
        ...(b.txHash ? { txHash: b.txHash } : {}),
      }
    );
  }

  #request(b: BatchRow): PutRequest<"afr.batch.v1"> {
    const { pub } = decodeFrame(b.frame);
    const last = pub.records.at(-1) as (typeof pub.records)[number];
    return {
      schema: "afr.batch.v1",
      attrs: {
        agent_key: this.#o.agentKey,
        lane: BigInt(pub.lane),
        seq_from: BigInt(pub.seq_from),
        seq_to: BigInt(pub.seq_to),
        chain_root: pub.chain_root as Hex,
        prev_chain_root: pub.prev_chain_root as Hex,
        batch_root: pub.batch_root as Hex,
        session_key: pub.session_keys[last.sk] as Hex,
        epoch_id: BigInt(pub.epoch_id),
        record_count: BigInt(pub.records.length),
        privacy: BigInt(this.#o.privacy),
        ...(this.#o.privacy >= 1 && pub.flags ? pub.flags : {}),
      },
      payload: b.frame,
      expiresAt: this.#o.expiresAt,
      readonly: true,
      permissionlessExtension: true,
      lock: true,
      idempotencyKey: this.#idempotencyKey(b),
    };
  }

  #fail(b: BatchRow, state: BatchRow["state"], e: unknown) {
    const code = (e as { code?: string })?.code ?? "UNKNOWN";
    this.#o.journal.updateBatch(b.seqFrom, { state, lastError: code });
    this.#o.logger?.warn(
      { code, seq_from: b.seqFrom.toString(), state },
      "batch upload step failed",
    );
    return code;
  }

  /** Readback: the stored entity must carry exactly our frame. */
  async #verify(b: BatchRow, key: Hex): Promise<StepResult> {
    const e = await this.#o.store.get(key, "afr.batch.v1");
    const ok =
      !!e && e.payload.length === b.frame.length && e.payload.every((x, i) => x === b.frame[i]);
    if (!ok) {
      this.#fail(b, "receipt_confirmed", new AfrError("READBACK_MISMATCH", "readback differs"));
      return "waiting";
    }
    this.#pending.delete(b.seqFrom);
    this.#markVerified(b, key);
    return "progress";
  }

  #markVerified(b: BatchRow, key: Hex) {
    this.#o.journal.atomically(() => {
      this.#o.journal.updateBatch(b.seqFrom, { state: "verified", entityKey: key });
      this.#o.onVerified?.(b, key, this.#request(b));
    });
  }

  /** Drives the lowest unverified batch by one transition. */
  async step(): Promise<StepResult> {
    const { journal, store } = this.#o;
    const b = journal.nextUnverifiedBatch();
    if (!b) return "idle";
    switch (b.state) {
      case "sealed":
      case "failed": {
        const attempts = b.state === "failed" ? b.attempts + 1 : b.attempts;
        journal.updateBatch(b.seqFrom, { state: "prepared", attempts });
        return "progress";
      }
      case "prepared": {
        const { pub } = decodeFrame(b.frame);
        if (this.#o.canSubmit && !(await this.#o.canSubmit(pub))) return "waiting";
        try {
          const w = await store.put(this.#request(b));
          this.#pending.set(b.seqFrom, w);
          journal.updateBatch(b.seqFrom, {
            state: "submitting",
            ...(w.predictedKey ? { predictedKey: w.predictedKey } : {}),
            ...(w.txHash ? { txHash: w.txHash } : {}),
          });
          return "progress";
        } catch (e) {
          // anything but a proven not-sent error may have reached the chain: reconcile, never resend
          const code = (e as { code?: string })?.code ?? "";
          this.#fail(b, NOT_SENT.has(code) ? "prepared" : "submitting", e);
          return "waiting";
        }
      }
      case "submitting": {
        const w = this.#write(b);
        if (this.#pending.has(b.seqFrom)) {
          try {
            const ref = await store.await(w);
            this.#pending.delete(b.seqFrom);
            this.#markVerified(b, ref.key);
            return "progress";
          } catch (e) {
            this.#pending.delete(b.seqFrom); // next step reconciles from the journal
            this.#fail(b, "submitting", e);
            return "waiting";
          }
        }
        const r = await store.reconcile(w).catch((e) => {
          this.#fail(b, "submitting", e);
          return undefined;
        });
        if (!r) return "waiting";
        switch (r.state) {
          case "confirmed":
            journal.updateBatch(b.seqFrom, { state: "receipt_confirmed", entityKey: r.ref.key });
            return this.#verify(b, r.ref.key);
          case "reverted":
            this.#fail(b, "failed", new AfrError("REVERTED", r.reason));
            return "progress";
          case "not_sent":
            journal.updateBatch(b.seqFrom, { state: "prepared" });
            return "progress";
          case "uncertain":
            this.#fail(b, "submitting", new AfrError("UNCERTAIN", "nonce consumed by another tx"));
            return "waiting";
        }
        return "waiting";
      }
      case "receipt_confirmed":
        return b.entityKey ? this.#verify(b, b.entityKey) : "waiting";
      default:
        return "idle";
    }
  }

  /** Steps until idle or blocked; returns the number of transitions made. */
  async drain(maxSteps = 10_000): Promise<number> {
    let n = 0;
    while (n < maxSteps && (await this.step()) === "progress") n++;
    return n;
  }
}
