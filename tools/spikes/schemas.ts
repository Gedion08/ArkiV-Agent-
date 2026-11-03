// Copy of the L3 §5 [NORMATIVE] Batch schema for the spikes (packages/arkiv will own the real one).
import { addr, bool, bytes, defineSchema, str, u64 } from "@arkiv-network/sdk/schema";
import { type Hex, toHex } from "viem";

export const Batch = defineSchema("afr.batch.v1", {
  agent_key: str().indexed(),
  lane: u64().indexed(),
  seq_from: u64().indexed(),
  seq_to: u64().indexed(),
  chain_root: str().indexed(),
  prev_chain_root: str(),
  batch_root: str(),
  session_key: addr().indexed(),
  epoch_id: u64(),
  record_count: u64(),
  privacy: u64(),
  has_tx: bool().indexed().optional(),
  has_block: bool().indexed().optional(),
  has_unapproved_tx: bool().indexed().optional(),
  has_violation: bool().indexed().optional(),
  frame: bytes(),
});

const h32 = (s: string) => toHex(new TextEncoder().encode(s.padEnd(32, "-").slice(0, 32))) as Hex;

/** Realistic attribute values (all 64-hex strings full length) around a frame of `frameBytes`. */
export function batchValues(agentKey: Hex, seqFrom: bigint, frameBytes: number, session: Hex) {
  const frame = new Uint8Array(frameBytes);
  crypto.getRandomValues(frame.subarray(0, Math.min(frameBytes, 65536)));
  for (let i = 65536; i < frameBytes; i += 65536)
    crypto.getRandomValues(frame.subarray(i, Math.min(frameBytes, i + 65536)));
  return {
    agent_key: agentKey,
    lane: u64(0n),
    seq_from: u64(seqFrom),
    seq_to: u64(seqFrom + 99n),
    chain_root: h32(`chain${seqFrom}`),
    prev_chain_root: h32(`prev${seqFrom}`),
    batch_root: h32(`batch${seqFrom}`),
    session_key: addr(session),
    epoch_id: u64(352n),
    record_count: u64(100n),
    privacy: u64(1n),
    has_tx: bool(true),
    has_block: bool(false),
    has_unapproved_tx: bool(false),
    has_violation: bool(false),
    frame: bytes(frame),
  };
}
