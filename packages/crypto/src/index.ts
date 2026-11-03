// @afr/crypto: L4 primitives. P1 ships only synchronous AES-256-GCM (journal at-rest sealing);
// DEK/KEK/HPKE/HMAC commitments arrive in P2.
import { gcm } from "@noble/ciphers/aes.js";

export const PACKAGE_NAME = "@afr/crypto";

export class CryptoError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
  }
}

function check(key: Uint8Array, iv: Uint8Array) {
  if (key.length !== 32) throw new CryptoError("KEY_INVALID", "AES-256-GCM key must be 32 bytes");
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
