// L6 §4.1 batch reconciliation (P4-03): intents lost on the way to the API are recovered from the
// tx_commitments / nonce_commitments in batch public sections on Arkiv. Arkiv is open-write, so a batch counts
// only if it decodes, matches its attributes and is signed by a session key the recorder registered for the
// lane: the same trust as an API intent (both come from the recorder's credentials).
//
// shortcut: no delegation time bounds or operator-signature check here; DELEGATION_MISUSE is the log
// auditor's (P4-05), which runs the verifier's full delegation rules over the same batches.
import {
  agentKey as agentKeyOf,
  type BatchPublicV1,
  batchDigest,
  recoverRecordSigner,
} from "@afr/core";
import { type BatchEntity, decodeFrame, type EvidenceStore, listBatches } from "@afr/store";
import type { Hex } from "viem";
import type { ReconcileDb } from "./db.js";

export interface ReconcileOptions {
  db: ReconcileDb;
  store: EvidenceStore;
  /** agents.id (uuid) */
  agentId: string;
  agentKey: Hex;
  lane: number;
  /** Writer allowlist (the registration's afr.arkiv.writers); without it every writer's entities are read. */
  writers?: Hex[];
}

/** Reconciles a lane from its cursor; returns how many batches were added. Stops at a gap until it fills. */
export async function reconcileLane(o: ReconcileOptions): Promise<number> {
  let next = await o.db.reconcileCursor(o.agentId, o.lane);
  let added = 0;
  for await (const b of listBatches(o.store, {
    agentKey: o.agentKey,
    lane: BigInt(o.lane),
    fromSeq: next,
    ...(o.writers ? { writers: o.writers } : {}),
  })) {
    if (b.attrs.seq_from > next) break; // a gap: SEQ_GAP is the log auditor's
    if (b.attrs.seq_from < next) continue; // a duplicate of a range already taken
    const pub = await validPub(o, b);
    if (!pub) continue; // forged or unsigned: a valid duplicate may follow
    await o.db.addBatchCommitments(
      o.agentId,
      o.lane,
      b.attrs.seq_to,
      pub.tx_commitments as Hex[],
      pub.nonce_commitments as Hex[],
    );
    next = b.attrs.seq_to + 1n;
    added++;
  }
  return added;
}

async function validPub(o: ReconcileOptions, b: BatchEntity): Promise<BatchPublicV1 | undefined> {
  let p: BatchPublicV1;
  try {
    p = decodeFrame(b.payload).pub;
  } catch {
    return undefined;
  }
  if (
    agentKeyOf(p.agent_id) !== o.agentKey ||
    BigInt(p.lane) !== b.attrs.lane ||
    BigInt(p.seq_from) !== b.attrs.seq_from ||
    BigInt(p.seq_to) !== b.attrs.seq_to
  )
    return undefined;
  const signer = await recoverRecordSigner(
    batchDigest({
      agentKey: o.agentKey,
      lane: p.lane,
      seqFrom: BigInt(p.seq_from),
      seqTo: BigInt(p.seq_to),
      batchRoot: p.batch_root as Hex,
      prevChainRoot: p.prev_chain_root as Hex,
      chainRoot: p.chain_root as Hex,
      payloadCtHash: p.payload_ct_hash as Hex,
    }),
    p.batch_sig as Hex,
  ).catch(() => undefined);
  if (!signer || !p.session_keys.some((k) => k.toLowerCase() === signer)) return undefined;
  return (await o.db.isSessionKey(o.agentId, o.lane, signer)) ? p : undefined;
}
