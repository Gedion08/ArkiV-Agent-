// Reader-key backup `.afrkey` (L4 §6) [NORMATIVE]:
// { v:1, x25519_pub, kdf:"argon2id", m, t, p, salt, iv, ct }, ct = AES-GCM(Argon2id(passphrase), secret).
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { bytesToHex, type Hex, hexToBytes, isHex } from "viem";
import { aesGcmOpen, aesGcmSeal, CryptoError } from "./aes.js";
import { kekIdFor } from "./batch.js";
import { openKeygrant, sealKeygrant } from "./keygrant.js";

export interface AfrKeyFile {
  v: 1;
  x25519_pub: Hex;
  kdf: "argon2id";
  /** KiB */
  m: number;
  t: number;
  p: number;
  salt: Hex;
  iv: Hex;
  ct: Hex;
}

export interface ReaderKey {
  pub: Hex;
  priv: Uint8Array;
}

const NO_AAD = new Uint8Array(0);
const DEFAULT_KDF = { m: 65536, t: 3, p: 1 };
/** Import bounds: a crafted file can't make us burn more than 1 GiB or run forever. */
const MAX = { m: 1 << 20, t: 10, p: 4 };

const kdf = (passphrase: string, salt: Uint8Array, o: { m: number; t: number; p: number }) =>
  argon2idAsync(passphrase, salt, { m: o.m, t: o.t, p: o.p, dkLen: 32 });

/** Throws INVALID_KEY unless `priv` opens what is sealed to `pub`. */
async function assertPair(r: ReaderKey): Promise<void> {
  const zero = `0x${"00".repeat(32)}` as Hex;
  const key = randomBytes(32);
  const kek = { epochId: 0, kekId: kekIdFor(zero, 0, key), key };
  try {
    await openKeygrant(
      { ...(await sealKeygrant(kek, r.pub, zero)), epochId: 0, kekId: kek.kekId },
      r.priv,
      zero,
    );
  } catch {
    throw new CryptoError("INVALID_KEY", "private key does not match x25519_pub");
  }
}

/** Encrypts a reader private key under a passphrase. `kdfParams` below the L4 §6 defaults are for tests. */
export async function exportReaderBackup(
  r: ReaderKey,
  passphrase: string,
  kdfParams: { m: number; t: number; p: number } = DEFAULT_KDF,
): Promise<AfrKeyFile> {
  if (r.priv.length !== 32) throw new CryptoError("INVALID_KEY", "reader key must be 32 bytes");
  await assertPair(r);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const k = await kdf(passphrase, salt, kdfParams);
  const ct = aesGcmSeal(k, iv, r.priv, NO_AAD);
  k.fill(0);
  return {
    v: 1,
    x25519_pub: r.pub.toLowerCase() as Hex,
    kdf: "argon2id",
    ...kdfParams,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ct: bytesToHex(ct),
  };
}

const int = (x: unknown, lo: number, hi: number) =>
  typeof x === "number" && Number.isInteger(x) && x >= lo && x <= hi;
const hexOf = (x: unknown, len?: number) =>
  typeof x === "string" &&
  isHex(x, { strict: true }) &&
  (len === undefined || x.length === 2 + 2 * len);

/** Untrusted input (a file). BACKUP_PASSPHRASE: wrong passphrase or tampered file. */
export async function importReaderBackup(file: unknown, passphrase: string): Promise<ReaderKey> {
  const f = file as Partial<AfrKeyFile> | null;
  if (
    !f ||
    typeof f !== "object" ||
    f.v !== 1 ||
    f.kdf !== "argon2id" ||
    !int(f.p, 1, MAX.p) ||
    !int(f.m, 8 * (f.p as number), MAX.m) ||
    !int(f.t, 1, MAX.t) ||
    !hexOf(f.x25519_pub, 32) ||
    !hexOf(f.salt) ||
    (f.salt as string).length < 2 + 32 ||
    !hexOf(f.iv, 12) ||
    !hexOf(f.ct, 48)
  )
    throw new CryptoError("INVALID_KEY", "not a v1 .afrkey file");
  const k = await kdf(passphrase, hexToBytes(f.salt as Hex), f as AfrKeyFile);
  let priv: Uint8Array;
  try {
    priv = aesGcmOpen(k, hexToBytes(f.iv as Hex), hexToBytes(f.ct as Hex), NO_AAD);
  } catch {
    throw new CryptoError("BACKUP_PASSPHRASE", "wrong passphrase or damaged backup");
  } finally {
    k.fill(0);
  }
  const r = { pub: (f.x25519_pub as Hex).toLowerCase() as Hex, priv };
  await assertPair(r);
  return r;
}
