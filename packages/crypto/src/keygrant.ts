// Keygrants (L4 §5) [NORMATIVE] and reader keys (§6): the epoch KEK sealed to a reader's X25519 key with
// HPKE base mode, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
import { Aes256Gcm, CipherSuite } from "@hpke/core";
import { DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/dhkem-x25519";
import {
  bytesToHex,
  concat,
  type Hex,
  hexToBytes,
  numberToBytes,
  stringToBytes,
  toBytes,
} from "viem";
import { CryptoError } from "./aes.js";
import { type EpochKek, kekIdFor } from "./batch.js";

/** L4 §5 info domain. */
const INFO_DOMAIN = "AFR_KEYGRANT_V1";

/** The L4 §5 suite (0x0020 / 0x0001 / 0x0002). Noble-backed X25519, so it runs where WebCrypto lacks it. */
export const KEYGRANT_SUITE = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

function info(agentKey: Hex, epochId: number): Uint8Array {
  const ak = toBytes(agentKey);
  if (ak.length !== 32) throw new CryptoError("INVALID_KEY", "agent_key must be 32 bytes");
  return concat([stringToBytes(INFO_DOMAIN), ak, numberToBytes(epochId, { size: 4 })]);
}

function key32(h: Hex, what: string): Uint8Array {
  const b = hexToBytes(h);
  if (b.length !== 32) throw new CryptoError("INVALID_KEY", `${what} must be 32 bytes`);
  return b;
}

/**
 * (enc, ct) = HPKE.Seal(pkR = reader, info, aad = kek_id, KEK): enc 32 B, ct 48 B.
 * `ekm` (vectors only) fixes the ephemeral key.
 */
export async function sealKeygrant(
  kek: EpochKek,
  readerPub: Hex,
  agentKey: Hex,
  ekm?: Uint8Array,
): Promise<{ enc: Uint8Array; ct: Uint8Array }> {
  const pk = key32(readerPub, "reader key");
  const recipientPublicKey = await KEYGRANT_SUITE.kem.deserializePublicKey(pk).catch(() => {
    throw new CryptoError("INVALID_KEY", "reader key is not an X25519 public key");
  });
  const r = await KEYGRANT_SUITE.seal(
    { recipientPublicKey, info: info(agentKey, kek.epochId), ...(ekm ? { ekm } : {}) },
    kek.key,
    hexToBytes(kek.kekId),
  );
  return { enc: new Uint8Array(r.enc), ct: new Uint8Array(r.ct) };
}

/** Opens a keygrant and checks the KEK against its kek_id. HPKE_OPEN_FAILED: not for this reader key. */
export async function openKeygrant(
  grant: { enc: Uint8Array; ct: Uint8Array; epochId: number; kekId: Hex },
  readerPriv: Uint8Array,
  agentKey: Hex,
): Promise<EpochKek> {
  if (grant.enc.length !== 32 || grant.ct.length !== 48)
    throw new CryptoError("HPKE_OPEN_FAILED", "malformed keygrant");
  const inf = info(agentKey, grant.epochId);
  let key: Uint8Array;
  try {
    const recipientKey = await KEYGRANT_SUITE.kem.deserializePrivateKey(readerPriv);
    key = new Uint8Array(
      await KEYGRANT_SUITE.open(
        { recipientKey, enc: grant.enc, info: inf },
        grant.ct,
        hexToBytes(grant.kekId),
      ),
    );
  } catch {
    throw new CryptoError("HPKE_OPEN_FAILED", "keygrant does not open with this reader key");
  }
  const kekId = grant.kekId.toLowerCase() as Hex;
  if (key.length !== 32 || kekIdFor(agentKey, grant.epochId, key) !== kekId)
    throw new CryptoError("KEK_ID_MISMATCH", "keygrant KEK does not match its kek_id");
  return { epochId: grant.epochId, kekId, key };
}

/** A new X25519 reader key pair (L4 §6), as raw 32-byte keys. */
export async function generateReaderKey(): Promise<{ pub: Hex; priv: Uint8Array }> {
  const kem = KEYGRANT_SUITE.kem;
  const kp = await kem.generateKeyPair();
  return {
    pub: bytesToHex(new Uint8Array(await kem.serializePublicKey(kp.publicKey))),
    priv: new Uint8Array(await kem.serializePrivateKey(kp.privateKey)),
  };
}
