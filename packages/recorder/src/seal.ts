// Batch sealing (L1 §5, L3 §4, L4 §3, L6 flag semantics): records → signed, encrypted frame.
// Pure apart from the injected randomness; the Batcher owns triggers and persistence.
import {
  AfrError,
  type BatchPublicV1,
  batchDigest,
  batchRoot,
  buildBody,
  chainRoot,
  LIMITS,
  type RecordBodyV1,
  type RecordHeaderV1,
  type SyncSigner,
} from "@afr/core";
import { type EpochKek, encryptBatch, nonceCommit, txCommit, userOpCommit } from "@afr/crypto";
import { encodeBody, encodeFrame, packPlaintext } from "@afr/store";
import { bytesToHex, type Hex } from "viem";

export interface SealRecord {
  seq: bigint;
  header: RecordHeaderV1;
  headerJcs: string;
  body: RecordBodyV1;
  hash: Hex;
  sig: Hex;
  sessionKey: Hex;
}

export interface SealContext {
  agentId: string;
  agentKey: Hex;
  lane: number;
  privacy: 0 | 1 | 2;
  /** L3 §4 padding buckets (privacy 0 only). */
  padding: boolean;
  kek: EpochKek;
  /** L4 §10 watch key; without it the commitment lists are empty. */
  watchKey?: Uint8Array;
  /** L6 has_unapproved_tx threshold; without it no tx counts as high-value. */
  approvalThresholdCents?: bigint;
  /** Session-key signers this process still holds. */
  signerFor: (address: Hex) => SyncSigner | undefined;
  /** ADR-024 fallback: the current session key, used when no record key of the batch is held. */
  batchSigner: () => { address: Hex; signer: SyncSigner };
  random: (n: number) => Uint8Array;
}

export interface SealedBatch {
  seqFrom: bigint;
  seqTo: bigint;
  pub: BatchPublicV1;
  frame: Uint8Array;
}

type Flags = NonNullable<BatchPublicV1["flags"]>;

/** L6 "Flag semantics", computed within the batch (an approval in a later batch doesn't clear it). */
export function batchFlags(headers: RecordHeaderV1[], thresholdCents?: bigint): Flags {
  const approvedRefs = new Set<string>();
  const requestOf = new Map<string, string>(); // approval_request seq → the seq it refers to
  for (const h of headers) {
    if (h.type === "approval_request" && h.ref_seq) requestOf.set(h.seq, h.ref_seq);
    if (h.type === "approval" && h.approval?.decision === "approved" && h.ref_seq) {
      approvedRefs.add(h.ref_seq);
      const via = requestOf.get(h.ref_seq) ?? requestOf.get(h.approval.request_seq);
      if (via) approvedRefs.add(via);
    }
  }
  return {
    has_tx: headers.some((h) => h.type === "tx_sign" || h.type === "msg_sign"),
    has_block: headers.some((h) => h.type === "policy_block"),
    has_unapproved_tx:
      thresholdCents !== undefined &&
      headers.some(
        (h) =>
          h.type === "tx_sign" &&
          h.tx?.value_usd_cents !== undefined &&
          BigInt(h.tx.value_usd_cents) >= thresholdCents &&
          !approvedRefs.has(h.seq),
      ),
    has_violation: headers.some(
      (h) => h.policy?.decision === "warn" || h.policy?.decision === "violated",
    ),
  };
}

function shuffle<T>(xs: T[], random: (n: number) => Uint8Array): T[] {
  const out = [...xs];
  for (let i = out.length - 1; i > 0; i--) {
    const r = new DataView(random(4).buffer).getUint32(0) % (i + 1);
    [out[i], out[r]] = [out[r] as T, out[i] as T];
  }
  return out;
}

/** ADR-015 commitments for every tx in the batch, deduplicated and order-shuffled. */
function commitments(headers: RecordHeaderV1[], ctx: SealContext) {
  const tx = new Set<Hex>();
  const nonce = new Set<Hex>();
  if (ctx.watchKey)
    for (const h of headers) {
      if (!h.tx) continue;
      const chain = BigInt(h.tx.chain_id);
      if (h.tx.tx_hash) tx.add(txCommit(ctx.watchKey, chain, h.tx.tx_hash as Hex));
      if (h.tx.user_op_hash) tx.add(userOpCommit(ctx.watchKey, chain, h.tx.user_op_hash as Hex));
      if (h.type === "tx_sign")
        nonce.add(nonceCommit(ctx.watchKey, chain, h.tx.from as Hex, BigInt(h.tx.nonce)));
    }
  return {
    tx_commitments: shuffle([...tx], ctx.random),
    nonce_commitments: shuffle([...nonce], ctx.random),
  };
}

/** One frame for exactly these records; throws FRAME_TOO_LARGE if it doesn't fit. */
export function sealOne(records: SealRecord[], prevChainRoot: Hex, ctx: SealContext): SealedBatch {
  const first = records[0];
  const last = records.at(-1);
  if (!first || !last) throw new AfrError("BATCH_EMPTY", "batches are never empty");
  const seqFrom = first.seq;
  const seqTo = last.seq;
  const root = batchRoot(records.map((r) => ({ seq: r.seq, hash: r.hash })));
  const chain = chainRoot(prevChainRoot, root, seqTo);
  const sessionKeys = [...new Set(records.map((r) => r.sessionKey.toLowerCase() as Hex))];
  // ADR-024: any listed key may sign; prefer the latest held record key, else list the current one
  const held = records.findLast((r) => ctx.signerFor(r.sessionKey));
  let signer = held && ctx.signerFor(held.sessionKey);
  if (!signer) {
    const current = ctx.batchSigner();
    signer = current.signer;
    sessionKeys.push(current.address.toLowerCase() as Hex);
  }
  const headers = records.map((r) => r.header);
  const plain = packPlaintext(
    { headers: records.map((r) => r.headerJcs), bodies: records.map((r) => encodeBody(r.body)) },
    { padding: ctx.privacy === 0 && ctx.padding },
  );
  const sealed = encryptBatch(
    plain,
    { agentKey: ctx.agentKey, lane: ctx.lane, seqFrom, seqTo, batchRoot: root },
    ctx.kek,
    ctx.random,
  );
  const digest = batchDigest({
    agentKey: ctx.agentKey,
    lane: ctx.lane,
    seqFrom,
    seqTo,
    batchRoot: root,
    prevChainRoot,
    chainRoot: chain,
    payloadCtHash: sealed.payloadCtHash,
  });
  const pub: BatchPublicV1 = {
    v: 1,
    agent_id: ctx.agentId,
    lane: ctx.lane,
    seq_from: seqFrom.toString(),
    seq_to: seqTo.toString(),
    prev_chain_root: prevChainRoot,
    chain_root: chain,
    batch_root: root,
    session_keys: sessionKeys,
    records: records.map((r) => ({
      seq: r.seq.toString(),
      hash: r.hash,
      sig: r.sig,
      sk: sessionKeys.indexOf(r.sessionKey.toLowerCase() as Hex),
    })),
    ...commitments(headers, ctx),
    ...(ctx.privacy >= 1 ? { flags: batchFlags(headers, ctx.approvalThresholdCents) } : {}),
    epoch_id: ctx.kek.epochId,
    kek_id: ctx.kek.kekId,
    wrapped_dek: bytesToHex(sealed.wrappedDek),
    iv: bytesToHex(sealed.iv),
    payload_ct_hash: sealed.payloadCtHash,
    batch_sig: signer.signDigest(digest),
  };
  return { seqFrom, seqTo, pub, frame: encodeFrame({ pub, ct: sealed.ct }) };
}

const isTooLarge = (e: unknown) => (e as { code?: string })?.code === "FRAME_TOO_LARGE";

/** Re-truncates every body part to `maxBytes`; commitments in the header still cover the full values. */
function shrinkBody(body: RecordBodyV1, maxBytes: number): RecordBodyV1 {
  const already = new Set(body.truncated?.map((t) => t.field));
  const { salt, truncated = [], redacted, ...parts } = body;
  const fresh = Object.fromEntries(Object.entries(parts).filter(([k]) => !already.has(k)));
  const { body: rebuilt } = buildBody(fresh, salt as Hex, { maxBytes });
  for (const [k, v] of Object.entries(parts))
    if (already.has(k) && typeof v === "string")
      (rebuilt as Record<string, unknown>)[k] = v.slice(0, maxBytes);
  const all = [...truncated, ...(rebuilt.truncated ?? [])];
  return {
    ...rebuilt,
    ...(all.length ? { truncated: all } : {}),
    ...(redacted ? { redacted } : {}),
  };
}

/**
 * L2 §9: seal `records` as one or more consecutive frames, each ≤ BATCH_MAX_FRAME_BYTES. A frame that
 * doesn't fit splits at the midpoint (any part is signable, ADR-024); a single record that doesn't
 * fit has its body truncated harder.
 */
export function sealBatches(
  records: SealRecord[],
  prevChainRoot: Hex,
  ctx: SealContext,
  onEvent: (code: "BODY_TRUNCATED_FOR_FRAME" | "BATCH_SPLIT") => void = () => {},
): SealedBatch[] {
  try {
    return [sealOne(records, prevChainRoot, ctx)];
  } catch (e) {
    if (!isTooLarge(e)) throw e;
  }
  if (records.length === 1) {
    const r = records[0] as SealRecord;
    for (let max = LIMITS.MAX_BODY_BYTES_DEFAULT / 2; max >= 64; max /= 2) {
      try {
        const out = sealOne([{ ...r, body: shrinkBody(r.body, max) }], prevChainRoot, ctx);
        onEvent("BODY_TRUNCATED_FOR_FRAME");
        return [out];
      } catch (e) {
        if (!isTooLarge(e)) throw e;
      }
    }
    throw new AfrError(
      "FRAME_TOO_LARGE",
      "a single record exceeds the frame size even when truncated",
    );
  }
  const cut = records.length >> 1;
  onEvent("BATCH_SPLIT");
  const left = sealBatches(records.slice(0, cut), prevChainRoot, ctx, onEvent);
  const tip = (left.at(-1) as SealedBatch).pub.chain_root as Hex;
  return [...left, ...sealBatches(records.slice(cut), tip, ctx, onEvent)];
}
