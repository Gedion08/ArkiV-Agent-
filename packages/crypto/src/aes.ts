// AES-256-GCM (noble, sync, isomorphic) and at-rest sealing (L4 §12).
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/hashes/utils.js";

/** Codes (L4 §12): INVALID_KEY, AAD_MISMATCH, DECRYPT_FAILED, KEK_ID_MISMATCH, HPKE_OPEN_FAILED, BACKUP_PASSPHRASE, CRYPTO_UNAVAILABLE. Messages never carry key material or plaintext. */
export class CryptoError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
  }
}

function check(key: Uint8Array, iv: Uint8Array) {
  if (key.length !== 32) throw new CryptoError("INVALID_KEY", "AES-256-GCM key must be 32 bytes");
  if (iv.length !== 12) throw new CryptoError("IV_INVALID", "AES-GCM IV must be 12 bytes");
}

/** AES-256-GCM encrypt. Returns ciphertext ‖ 16-byte tag. IV must be unique per key. */
export function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  check(key, iv);
  return gcm(key, iv, aad).encrypt(plaintext);
}

/** AES-256-GCM decrypt. Throws DECRYPT_FAILED on a wrong key, IV, AAD or tampered ciphertext. */
export function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  check(key, iv);
  try {
    return gcm(key, iv, aad).decrypt(ciphertext);
  } catch {
    throw new CryptoError("DECRYPT_FAILED", "authentication failed");
  }
}

/** iv(12) ‖ AES-256-GCM(key, iv, bytes, aad). For recorder-local secrets (e.g. sealed epoch KEKs). */
export function sealAtRest(
  key: Uint8Array,
  bytes: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  random: (n: number) => Uint8Array = randomBytes,
): Uint8Array {
  const iv = random(12);
  const ct = aesGcmSeal(key, iv, bytes, aad);
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

export function openAtRest(
  key: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (sealed.length < 12 + 16) throw new CryptoError("DECRYPT_FAILED", "sealed value too short");
  return aesGcmOpen(key, sealed.subarray(0, 12), sealed.subarray(12), aad);
}
