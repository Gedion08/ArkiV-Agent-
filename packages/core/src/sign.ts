// Session-key signing (L1 §3.4) [NORMATIVE]: EIP-191 personal_sign over the 32 raw bytes.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { type Hex, hashMessage, recoverMessageAddress, toBytes, toHex } from "viem";
import { publicKeyToAddress } from "viem/accounts";

export interface Signer {
  /** Lowercase address. */
  address: Hex;
  /** EIP-191 sign over the raw 32-byte digest (= viem `signMessage({ message: { raw } })`). */
  signDigest(raw: Hex): Promise<Hex> | Hex;
}

/** Synchronous noble signer for the hot path. Deterministic (RFC 6979), low-s. */
/** A Signer whose signDigest is synchronous (assignable to Signer). */
export interface SyncSigner {
  address: Hex;
  signDigest(raw: Hex): Hex;
}

export function localSigner(privateKey: Hex): SyncSigner {
  const sk = toBytes(privateKey);
  secp256k1.Point.BASE.precompute(8, false); // memoised base-point table: ~20% faster signing
  const address = publicKeyToAddress(toHex(secp256k1.getPublicKey(sk, false))).toLowerCase() as Hex;
  return {
    address,
    signDigest(raw) {
      const digest = toBytes(hashMessage({ raw }));
      const sig = secp256k1.Signature.fromBytes(
        secp256k1.sign(digest, sk, { prehash: false, format: "recovered" }),
        "recovered",
      );
      const rs = sig.toHex("compact");
      return `0x${rs}${(27 + (sig.recovery ?? 0)).toString(16)}` as Hex;
    },
  };
}

export async function signRecord(signer: Signer, recordHash: Hex): Promise<Hex> {
  return await signer.signDigest(recordHash);
}

/** Lowercase signer address of an EIP-191 raw-digest signature. */
export async function recoverRecordSigner(recordHash: Hex, sig: Hex): Promise<Hex> {
  const addr = await recoverMessageAddress({ message: { raw: recordHash }, signature: sig });
  return addr.toLowerCase() as Hex;
}
