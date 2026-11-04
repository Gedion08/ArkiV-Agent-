// L8 §2 recorder auth: `Authorization: Bearer afr_rk_<id>_<secret>` + `X-AFR-Timestamp` (unix s, ±5 min)
// + `X-AFR-Signature: hex(HMAC-SHA256(sha256(secret), METHOD\npath\nts\nhex(sha256(body))))`.
// The bearer proves the secret; the HMAC binds method, path, time and body. The DB keeps only
// sha256(secret), which is also the HMAC key, so a DB read alone can't pass the bearer check.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { RECORDER_KEY_RE, recorderStringToSign, signRecorderRequest } from "@afr/crypto";

export { RECORDER_KEY_RE, signRecorderRequest };
export const MAX_SKEW_S = 300;

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();

export function newRecorderKey(): { id: string; token: string; secretHash: Buffer } {
  const id = randomBytes(8).toString("hex");
  const secret = randomBytes(32).toString("hex");
  return { id, token: `afr_rk_${id}_${secret}`, secretHash: sha256(secret) };
}

export type RecorderAuthFailure = "MALFORMED" | "STALE" | "BAD_SECRET" | "BAD_SIGNATURE";

/** Server side: checks a request against the stored secret hash. */
export function checkRecorderRequest(
  req: { method: string; path: string; body: Buffer; secret: string; ts: string; sig: string },
  secretHash: Buffer,
  nowS: number,
): RecorderAuthFailure | undefined {
  if (!/^\d{1,12}$/.test(req.ts) || !/^[0-9a-f]{64}$/.test(req.sig)) return "MALFORMED";
  if (Math.abs(nowS - Number(req.ts)) > MAX_SKEW_S) return "STALE";
  if (!timingSafeEqual(sha256(req.secret), secretHash)) return "BAD_SECRET";
  const want = createHmac("sha256", secretHash)
    .update(recorderStringToSign(req.method, req.path, req.ts, req.body))
    .digest();
  return timingSafeEqual(want, Buffer.from(req.sig, "hex")) ? undefined : "BAD_SIGNATURE";
}
