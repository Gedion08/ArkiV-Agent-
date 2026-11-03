// Watch-key commitments (L4 §10) [NORMATIVE]: the hosted watcher matches txs without content access.
import { DOMAIN } from "@afr/core";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concat, type Hex, numberToBytes, stringToBytes, toBytes } from "viem";
import { CryptoError } from "./aes.js";

const u64 = (n: bigint) => numberToBytes(n, { size: 8 });

function bytesOf(v: Hex, len: number, what: string): Uint8Array {
  const b = toBytes(v);
  if (b.length !== len) throw new CryptoError("INVALID_KEY", `${what} must be ${len} bytes`);
  return b;
}

function mac(watchKey: Uint8Array, parts: Uint8Array[]): Hex {
  if (watchKey.length !== 32) throw new CryptoError("INVALID_KEY", "watch key must be 32 bytes");
  return bytesToHex(hmac(sha256, watchKey, concat(parts)));
}

/** HMAC-SHA256(watch_key, "AFR_TX_V1" ‖ u64be(chain_id) ‖ tx_hash). */
export function txCommit(watchKey: Uint8Array, chainId: bigint, txHash: Hex): Hex {
  return mac(watchKey, [stringToBytes(DOMAIN.TX), u64(chainId), bytesOf(txHash, 32, "tx_hash")]);
}

/** Same domain as txCommit, over the ERC-4337 user-op hash. */
export function userOpCommit(watchKey: Uint8Array, chainId: bigint, userOpHash: Hex): Hex {
  return mac(watchKey, [
    stringToBytes(DOMAIN.TX),
    u64(chainId),
    bytesOf(userOpHash, 32, "user_op_hash"),
  ]);
}

/** HMAC-SHA256(watch_key, "AFR_NONCE_V1" ‖ u64be(chain_id) ‖ from ‖ u64be(nonce)). */
export function nonceCommit(watchKey: Uint8Array, chainId: bigint, from: Hex, nonce: bigint): Hex {
  return mac(watchKey, [
    stringToBytes(DOMAIN.NONCE),
    u64(chainId),
    bytesOf(from, 20, "from"),
    u64(nonce),
  ]);
}
