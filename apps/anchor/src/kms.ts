// L5 §3.3 KMS signer: a viem account whose key never leaves AWS KMS (ECC_SECG_P256K1, SIGN_VERIFY).
// KMS signs the keccak digest (MessageType DIGEST); we parse its DER, normalise s to the low half
// (EIP-2) and find v by recovering both parities against the address from GetPublicKey.

import { AfrError } from "@afr/core";
import { GetPublicKeyCommand, type KMSClient, SignCommand } from "@aws-sdk/client-kms";
import {
  bytesToHex,
  type Hex,
  hashMessage,
  hashTypedData,
  keccak256,
  recoverAddress,
  type Signature,
  serializeSignature,
  serializeTransaction,
} from "viem";
import { publicKeyToAddress, toAccount } from "viem/accounts";
import type { AnchorSigner } from "./chain.js";

/** The two KMS calls the signer needs, so tests can stand in for AWS. */
export interface KmsApi {
  /** DER SubjectPublicKeyInfo. */
  publicKey(): Promise<Uint8Array>;
  /** DER ECDSA-Sig-Value over a 32-byte digest. */
  sign(digest: Uint8Array): Promise<Uint8Array>;
}

export function awsKms(client: Pick<KMSClient, "send">, keyId: string): KmsApi {
  return {
    async publicKey() {
      const r = await client.send(new GetPublicKeyCommand({ KeyId: keyId }));
      if (r.KeySpec !== "ECC_SECG_P256K1" || r.KeyUsage !== "SIGN_VERIFY" || !r.PublicKey)
        throw new AfrError("KMS_KEY_SPEC", "anchor key must be ECC_SECG_P256K1 / SIGN_VERIFY");
      return r.PublicKey;
    },
    async sign(digest) {
      const r = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: digest,
          MessageType: "DIGEST",
          SigningAlgorithm: "ECDSA_SHA_256",
        }),
      );
      if (!r.Signature) throw new AfrError("KMS_SIGN", "KMS returned no signature");
      return r.Signature;
    },
  };
}

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const bad = (msg: string) => new AfrError("KMS_DER", msg);

/** One DER TLV at `at` (short or long-form length); returns its value bounds. */
function tlv(b: Uint8Array, at: number, tag: number): { start: number; end: number } {
  if (b[at] !== tag) throw bad(`expected tag 0x${tag.toString(16)}`);
  let len = b[at + 1] ?? 0;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 2) throw bad("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | (b[start + i] ?? 0);
    start += n;
  }
  const end = start + len;
  if (end > b.length) throw bad("truncated");
  return { start, end };
}

/** The uncompressed point (0x04‖X‖Y) inside a secp256k1 SubjectPublicKeyInfo. */
export function spkiPoint(spki: Uint8Array): Hex {
  const seq = tlv(spki, 0, 0x30);
  const algo = tlv(spki, seq.start, 0x30);
  const bits = tlv(spki, algo.end, 0x03);
  if (bits.end !== seq.end || seq.end !== spki.length) throw bad("trailing bytes");
  const point = spki.subarray(bits.start + 1, bits.end); // skip the unused-bits byte
  if (spki[bits.start] !== 0 || point.length !== 65 || point[0] !== 0x04)
    throw bad("not an uncompressed EC point");
  return bytesToHex(point);
}

/** r and s from DER, with s moved to the low half of the curve order. */
export function derSignature(der: Uint8Array): { r: bigint; s: bigint } {
  const seq = tlv(der, 0, 0x30);
  if (seq.end !== der.length) throw bad("trailing bytes");
  const int = (at: number) => {
    const t = tlv(der, at, 0x02);
    if (t.end - t.start < 1 || t.end - t.start > 33) throw bad("bad integer");
    return { v: BigInt(bytesToHex(der.subarray(t.start, t.end))), end: t.end };
  };
  const r = int(seq.start);
  const s = int(r.end);
  if (s.end !== seq.end) throw bad("trailing bytes");
  if (r.v <= 0n || r.v >= N || s.v <= 0n || s.v >= N) throw bad("r or s out of range");
  return { r: r.v, s: s.v > N / 2n ? N - s.v : s.v };
}

const hex32 = (x: bigint) => `0x${x.toString(16).padStart(64, "0")}` as Hex;

export async function kmsAccount(kms: KmsApi): Promise<AnchorSigner> {
  const address = publicKeyToAddress(spkiPoint(await kms.publicKey()));
  const sign = async (hash: Hex): Promise<Signature> => {
    const { r, s } = derSignature(await kms.sign(Buffer.from(hash.slice(2), "hex")));
    for (const yParity of [0, 1]) {
      const sig = { r: hex32(r), s: hex32(s), yParity, v: 27n + BigInt(yParity) };
      if ((await recoverAddress({ hash, signature: sig })) === address) return sig;
    }
    throw new AfrError("KMS_RECOVER", "KMS signature does not recover to the key's address");
  };
  return toAccount({
    address,
    signMessage: async ({ message }) => serializeSignature(await sign(hashMessage(message))),
    signTypedData: async (td) => serializeSignature(await sign(hashTypedData(td as never))),
    async signTransaction(tx, o) {
      const serializer = o?.serializer ?? serializeTransaction;
      const unsigned = tx.type === "eip4844" ? { ...tx, sidecars: false as const } : tx;
      return serializer(tx, await sign(keccak256(await serializer(unsigned as never))));
    },
  }) as AnchorSigner;
}
