// keccak helpers + commitments (L1 §3.3) [NORMATIVE].
import { concat, type Hex, keccak256, stringToBytes, toBytes } from "viem";
import type { CommitDomain } from "./constants.js";
import { AfrError } from "./errors.js";
import { jcs, jcsData } from "./jcs.js";

const SALT_RE = /^0x[0-9a-f]{64}$/;

/** keccak256(utf8(jcs(value))) for hashed AFR structures (params_hash, policy_hash, …). */
export function keccakJcs(value: unknown): Hex {
  return keccak256(stringToBytes(jcs(value)));
}

/** keccak256(utf8(jcsData(value))) for captured data (truncation original_hash). */
export function keccakJcsData(value: unknown): Hex {
  return keccak256(stringToBytes(jcsData(value)));
}

/** commit = keccak256(0x01 ‖ salt[32] ‖ utf8(domain) ‖ 0x00 ‖ utf8(JCS(value))). */
export function commit(domain: CommitDomain, value: unknown, salt: Hex): Hex {
  if (!SALT_RE.test(salt))
    throw new AfrError("SALT_INVALID", "salt must be 32 bytes lowercase hex");
  return keccak256(
    concat([
      new Uint8Array([1]),
      toBytes(salt),
      stringToBytes(domain),
      new Uint8Array([0]),
      stringToBytes(jcsData(value)),
    ]),
  );
}
