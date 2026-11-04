// Cheap checkpoint validation (L5 §3.1 step 2): the batch entity exists and matches, and batch_sig is by
// one of its session keys that the recorder announced. The delegation chain back to the ERC-8004 operator
// is the verifier's job (L7); anchoring makes no claim about it.
import { agentKey as agentKeyOf, batchDigest, recoverRecordSigner } from "@afr/core";
import { decodeFrame, type EvidenceStore } from "@afr/store";
import type { Hex } from "viem";
import type { CheckpointRow } from "./db.js";

/** `retry`: may resolve by itself (Arkiv read lag, delegation notice not delivered yet). */
export type Verdict = { ok: true } | { ok: false; reason: string; retry?: true };

export async function validateCheckpoint(
  store: EvidenceStore,
  c: CheckpointRow,
  announced: Hex[],
): Promise<Verdict> {
  const e = await store.get(c.batchEntity, "afr.batch.v1");
  if (!e) return { ok: false, reason: "BATCH_NOT_FOUND", retry: true };
  const a = e.attrs;
  if (
    a.agent_key.toLowerCase() !== c.agentKey ||
    a.lane !== BigInt(c.lane) ||
    a.seq_to !== c.seqTo ||
    a.chain_root.toLowerCase() !== c.chainRoot
  )
    return { ok: false, reason: "ATTRS_MISMATCH" };
  let p: ReturnType<typeof decodeFrame>["pub"];
  try {
    p = decodeFrame(e.payload).pub;
  } catch {
    return { ok: false, reason: "FRAME_INVALID" };
  }
  if (
    agentKeyOf(p.agent_id) !== c.agentKey ||
    p.lane !== c.lane ||
    BigInt(p.seq_to) !== c.seqTo ||
    p.chain_root !== c.chainRoot
  )
    return { ok: false, reason: "ATTRS_MISMATCH" };
  const digest = batchDigest({
    agentKey: c.agentKey,
    lane: p.lane,
    seqFrom: BigInt(p.seq_from),
    seqTo: BigInt(p.seq_to),
    batchRoot: p.batch_root as Hex,
    prevChainRoot: p.prev_chain_root as Hex,
    chainRoot: p.chain_root as Hex,
    payloadCtHash: p.payload_ct_hash as Hex,
  });
  const signer = await recoverRecordSigner(digest, p.batch_sig as Hex).catch(() => undefined);
  const keys = p.session_keys.map((k) => k.toLowerCase());
  if (!signer || !keys.includes(signer)) return { ok: false, reason: "BATCH_SIG" };
  if (!announced.map((k) => k.toLowerCase()).includes(signer))
    return { ok: false, reason: "UNKNOWN_SESSION_KEY", retry: true };
  return { ok: true };
}
