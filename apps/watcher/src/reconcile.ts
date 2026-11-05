// L6 §4.1 batch reconciliation (P4-03): intents lost on the way to the API are recovered from the
// tx_commitments / nonce_commitments in batch public sections on Arkiv. Arkiv is open-write, so a batch counts
// only if it decodes, matches its attributes, and its batch_sig recovers to a listed session key that is
// (a) registered by the recorder for the lane (session_keys, not revoked) and (b) delegated by the agent's
// operator (L1 §7) at the time the batch was written: notBefore ≤ t ≤ notAfter + 1 h, no revocation
// effective at or before t. t is the batch entity's Arkiv block time; anchors (the verifier's bound) come
// later, so the write time is the tighter bound.
import {
  agentKey as agentKeyOf,
  type BatchPublicV1,
  batchDigest,
  recoverRecordSigner,
} from "@afr/core";
import {
  type BatchEntity,
  decodeFrame,
  type EvidenceStore,
  type Frame,
  listBatches,
} from "@afr/store";
import {
  type DelegationSet,
  type IdentityReader,
  loadDelegations,
  recordDelegations,
} from "@afr/verifier";
import type { Hex } from "viem";
import type { ReconcileDb } from "./db.js";

/** Arkiv block time (L3 §2), to date an entity from its creation block. */
const ARKIV_BLOCK_S = 2n;
/** L1 §7: a record must be anchored before notAfter + 1 h. */
const DELEGATION_GRACE_S = 3600n;
/** Slack for the block-time estimate against notBefore. */
const SKEW_S = 60n;

export interface ReconcileOptions {
  db: ReconcileDb;
  store: EvidenceStore;
  identity: IdentityReader;
  /** agents.id (uuid) */
  agentId: string;
  /** The ERC-8004 agent id (agents.agent_id), whose operator signs delegations. */
  agent: string;
  lane: number;
  /** Writer allowlist (the registration's afr.arkiv.writers); without it every writer's entities are read. */
  writers?: Hex[];
}

/** Reconciles a lane from its cursor; returns how many batches were added. Stops at a gap until it fills. */
export async function reconcileLane(o: ReconcileOptions): Promise<number> {
  const agentKey = agentKeyOf(o.agent);
  let next = await o.db.reconcileCursor(o.agentId, o.lane);
  let added = 0;
  let head: { block: bigint; timestamp: number } | undefined;
  let delegations: DelegationSet | undefined;
  for await (const b of listBatches(o.store, {
    agentKey,
    lane: BigInt(o.lane),
    fromSeq: next,
    ...(o.writers ? { writers: o.writers } : {}),
  })) {
    if (b.attrs.seq_from > next) break; // a gap: SEQ_GAP is the log auditor's
    if (b.attrs.seq_from < next) continue; // a duplicate of a range already taken
    // loaded once per pass, and only when there is something to check (identity lookups cost RPC calls)
    head ??= await o.store.head();
    delegations ??= await loadDelegations(o.agent, {
      store: o.store,
      identity: o.identity,
      ...(o.writers ? { writers: o.writers } : {}),
    });
    const a = await authenticBatch(o.agent, agentKey, b);
    // forged, unsigned or out of delegation: a valid duplicate may follow
    if (!a || !delegatedAt(delegations, a.signer, o.lane, arkivTime(head, b))) continue;
    if (!(await o.db.isSessionKey(o.agentId, o.lane, a.signer))) continue;
    const pub = a.pub;
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

/** Estimated Arkiv write time (unix s) of a batch entity, from its creation block. */
export const arkivTime = (head: { block: bigint; timestamp: number }, b: BatchEntity) =>
  BigInt(head.timestamp) - (head.block - b.meta.createdAtBlock) * ARKIV_BLOCK_S;

/** A batch that decodes, matches its attrs and whose batch_sig recovers to one of its listed session keys. */
export async function authenticBatch(
  agent: string,
  agentKey: Hex,
  b: BatchEntity,
): Promise<{ frame: Frame; pub: BatchPublicV1; signer: Hex } | undefined> {
  let frame: Frame;
  try {
    frame = decodeFrame(b.payload);
  } catch {
    return undefined;
  }
  const p = frame.pub;
  if (
    p.agent_id !== agent ||
    BigInt(p.lane) !== b.attrs.lane ||
    BigInt(p.seq_from) !== b.attrs.seq_from ||
    BigInt(p.seq_to) !== b.attrs.seq_to
  )
    return undefined;
  const signer = await recoverRecordSigner(
    batchDigest({
      agentKey,
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
  return { frame, pub: p, signer };
}

/** L1 §7: delegated by the operator for the lane at t (notBefore ≤ t ≤ notAfter + 1 h), not revoked by t. */
export function delegatedAt(ds: DelegationSet, signer: Hex, lane: number, t: bigint): boolean {
  const revoked = ds.revokedAt.get(signer);
  return (
    (revoked === undefined || revoked > t) &&
    recordDelegations(ds, signer, lane).some(
      (d) => d.notBefore - SKEW_S <= t && t <= d.notAfter + DELEGATION_GRACE_S,
    )
  );
}
