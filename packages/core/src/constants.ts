// Constants registry: docs/01-architecture/ARCHITECTURE.md §21 [NORMATIVE].
import { type Hex, keccak256, stringToBytes } from "viem";

export const AFR_RECORD_VERSION = 1;
export const EIP712_DOMAIN_NAME = "AgentFlightRecorder";
export const EIP712_DOMAIN_VERSION = "1";

export const DOMAIN = {
  CHAIN: "AFR_CHAIN_V1",
  BATCH: "AFR_BATCH_V1",
  DEK: "AFR_DEK_V1",
  KEYGRANT: "AFR_KEYGRANT_V1",
  TX: "AFR_TX_V1",
  NONCE: "AFR_NONCE_V1",
  BATCH_AAD: "AFR_BATCH_AAD_V1",
  LOCK: "AFR_EVIDENCE_LOCK_V1",
} as const;

export const COMMIT_DOMAIN = {
  ARGS: "afr/args",
  RESULT: "afr/result",
  CONTEXT: "afr/context",
  OUTPUT: "afr/output",
  CALLDATA: "afr/calldata",
} as const;

export type CommitDomain = (typeof COMMIT_DOMAIN)[keyof typeof COMMIT_DOMAIN];

/** L1 §8: last 20 bytes of keccak256(utf8("AFR_EVIDENCE_LOCK_V1")). No private key exists for it. */
export function deriveLockAddress(): Hex {
  return `0x${keccak256(stringToBytes(DOMAIN.LOCK)).slice(-40)}`;
}

export const EVIDENCE_LOCK_ADDRESS = deriveLockAddress();

export const SCHEMA = {
  AGENT: "afr.agent.v1",
  DELEGATION: "afr.delegation.v1",
  REVOCATION: "afr.revocation.v1",
  BATCH: "afr.batch.v1",
  KEYGRANT: "afr.keygrant.v1",
  ANCHOR: "afr.anchor.v1",
  CHECKPOINT: "afr.checkpoint.v1",
  ATTESTATION: "afr.attestation.v1",
  ACTION: "afr.action.v1",
  READERKEY: "afr.readerkey.v1",
} as const;

export const LIMITS = {
  BATCH_TARGET_BYTES: 96 * 1024,
  BATCH_MAX_FRAME_BYTES: 120 * 1024, // < Arkiv 128 KiB bytes-per-create
  BATCH_MAX_AGE_MS: 5_000,
  HEARTBEAT_MS: 60_000,
  MAX_RECORDS_PER_BATCH: 1_000,
  MAX_HEADER_BYTES: 8 * 1024,
  MAX_BODY_BYTES_DEFAULT: 64 * 1024, // larger bodies are truncated + hashed (see L2)
  SESSION_KEY_MAX_TTL_S: 24 * 3600,
  WATCH_GRACE_MS: 60_000,
  ANCHOR_CADENCE_S: 600,
  ANCHOR_LAG_FACTOR: 3,
} as const;

export const PADDING_BUCKETS = [8, 16, 32, 64, 96, 120].map((k) => k * 1024);

export const CHAINS = {
  ARKIV_RABDI: 7794095,
  BASE: 8453,
  BASE_SEPOLIA: 84532,
} as const;

export const ZERO_HASH: Hex = `0x${"00".repeat(32)}`;
