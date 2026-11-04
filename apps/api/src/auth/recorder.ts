// L8 §2 recorder auth: `Authorization: Bearer afr_rk_<id>_<secret>` + `X-AFR-Timestamp` (unix s, ±5 min)
// + `X-AFR-Signature: hex(HMAC-SHA256(sha256(secret), METHOD\npath\nts\nhex(sha256(body))))`.
// The bearer proves the secret; the HMAC binds method, path, time and body. The DB keeps only
// sha256(secret), which is also the HMAC key, so a DB read alone can't pass the bearer check.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const RECORDER_KEY_RE = /^afr_rk_([0-9a-f]{16})_([0-9a-f]{64})$/;
export const MAX_SKEW_S = 300;

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();

export function newRecorderKey(): { id: string; token: string; secretHash: Buffer } {
  const id = randomBytes(8).toString("hex");
  const secret = randomBytes(32).toString("hex");
  return { id, token: `afr_rk_${id}_${secret}`, secretHash: sha256(secret) };
}

function stringToSign(method: string, path: string, ts: string, body: Buffer | string): string {
  return `${method.toUpperCase()}\n${path}\n${ts}\n${sha256(body).toString("hex")}`;
}

/** Client side (the recorder outbox, P2-14): headers for one request. */
export function signRecorderRequest(
  token: string,
  method: string,
  path: string,
  body: Buffer | string,
  nowS: number,
): Record<string, string> {
  const m = RECORDER_KEY_RE.exec(token);
  if (!m) throw new Error("not a recorder key");
  const ts = String(nowS);
  const sig = createHmac("sha256", sha256(m[2] as string))
    .update(stringToSign(method, path, ts, body))
    .digest("hex");
  return { authorization: `Bearer ${token}`, "x-afr-timestamp": ts, "x-afr-signature": sig };
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
    .update(stringToSign(req.method, req.path, req.ts, req.body))
    .digest();
  return timingSafeEqual(want, Buffer.from(req.sig, "hex")) ? undefined : "BAD_SIGNATURE";
}
