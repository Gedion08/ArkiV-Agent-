// L8 §2 recorder → API request signing, shared by the recorder outbox and apps/api.
// X-AFR-Signature = hex(HMAC-SHA256(sha256(secret), METHOD\npath\nts\nhex(sha256(body)))).
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, stringToBytes } from "viem";
import { CryptoError } from "./aes.js";

export const RECORDER_KEY_RE = /^afr_rk_([0-9a-f]{16})_([0-9a-f]{64})$/;

const bytes = (b: Uint8Array | string) => (typeof b === "string" ? stringToBytes(b) : b);

export function recorderStringToSign(
  method: string,
  path: string,
  ts: string,
  body: Uint8Array | string,
): string {
  return `${method.toUpperCase()}\n${path}\n${ts}\n${bytesToHex(sha256(bytes(body))).slice(2)}`;
}

/** sha256(secret): what the API stores, and the HMAC key. */
export const recorderSecretHash = (secret: string): Uint8Array => sha256(stringToBytes(secret));

/** Headers for one recorder request (`path` includes the query string, `nowS` is unix seconds). */
export function signRecorderRequest(
  token: string,
  method: string,
  path: string,
  body: Uint8Array | string,
  nowS: number,
): Record<string, string> {
  const m = RECORDER_KEY_RE.exec(token);
  if (!m) throw new CryptoError("INVALID_KEY", "not a recorder key (afr_rk_<id>_<secret>)");
  const ts = String(nowS);
  const sig = hmac(
    sha256,
    recorderSecretHash(m[2] as string),
    stringToBytes(recorderStringToSign(method, path, ts, body)),
  );
  return {
    authorization: `Bearer ${token}`,
    "x-afr-timestamp": ts,
    "x-afr-signature": bytesToHex(sig).slice(2),
  };
}
