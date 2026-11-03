// L1 §2 identifiers.
import { encodeAbiParameters, type Hex, keccak256, stringToBytes } from "viem";
import { AfrError } from "./errors.js";

const EIP155_RE = /^eip155:(0|[1-9][0-9]*):(0x[0-9a-f]{40}):(0|[1-9][0-9]*)$/;
const LOCAL_RE = /^local:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UINT256_MAX = 2n ** 256n - 1n;

export interface ParsedAgentId {
  chainId: bigint;
  registry: Hex;
  tokenId: bigint;
}

/** Strict parse of `eip155:<chainId>:<registry>:<tokenId>`. Throws `AGENT_ID_INVALID`. */
export function parseAgentId(id: string): ParsedAgentId {
  const m = EIP155_RE.exec(id);
  if (!m)
    throw new AfrError(
      "AGENT_ID_INVALID",
      "agent_id must be eip155:<chainId>:<0xlowerhex40>:<tokenId>",
    );
  const [, chainId, registry, tokenId] = m as unknown as [string, string, Hex, string];
  const parsed = { chainId: BigInt(chainId), registry, tokenId: BigInt(tokenId) };
  if (parsed.tokenId > UINT256_MAX || parsed.chainId > UINT256_MAX) {
    throw new AfrError("AGENT_ID_INVALID", "agent_id number out of range");
  }
  return parsed;
}

/** Dev-mode agents without an ERC-8004 identity: `local:<uuid-v4>` (verifier: "unanchored identity"). */
export function isLocalAgentId(id: string): boolean {
  return LOCAL_RE.test(id);
}

/** Throws unless `id` is a valid eip155 or local agent id. */
export function assertAgentId(id: string): void {
  if (!isLocalAgentId(id)) parseAgentId(id);
}

/** agent_key = keccak256(utf8(agent_id)). */
export function agentKey(id: string): Hex {
  assertAgentId(id);
  return keccak256(stringToBytes(id));
}

/** batch_id = keccak256(abi.encode(agent_key, lane, seq_from)). */
export function batchId(agentKeyHex: Hex, lane: number, seqFrom: bigint): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint32" }, { type: "uint64" }],
      [agentKeyHex, lane, seqFrom],
    ),
  );
}

/**
 * epoch_id = month * 16 + rotation, where month = months since 2025-01 (UTC).
 * The sub-index is always present so ids never collide across months (2026-11, rotation 0 → 352).
 */
export function epochIdFor(date: Date, rotation = 0): number {
  if (!Number.isInteger(rotation) || rotation < 0 || rotation > 15) {
    throw new AfrError("EPOCH_ROTATION_INVALID", "rotation must be an integer in 0..15");
  }
  const month = (date.getUTCFullYear() - 2025) * 12 + date.getUTCMonth();
  if (!Number.isFinite(month) || month < 0)
    throw new AfrError("EPOCH_DATE_INVALID", "date before 2025-01");
  return month * 16 + rotation;
}
