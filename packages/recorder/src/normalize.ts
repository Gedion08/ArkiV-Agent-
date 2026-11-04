// Capture normalisation (L2 §3.1). NFC is applied by @afr/core's JCS when hashing.
import { createHash } from "node:crypto";
import type { TxInfo } from "@afr/core";

const META_MAX_KEYS = 16;
const META_MAX_BYTES = 128;
const utf8Len = (s: string) => Buffer.byteLength(s, "utf8");

/** Trims meta to the header limits; overflow is dropped and flagged with meta.truncated = "1". */
export function normalizeMeta(
  meta: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!meta) return undefined;
  const out: Record<string, string> = {};
  let dropped = false;
  for (const [k, v] of Object.entries(meta)) {
    if (
      Object.keys(out).length >= META_MAX_KEYS - 1 ||
      utf8Len(k) > META_MAX_BYTES ||
      utf8Len(String(v)) > META_MAX_BYTES
    ) {
      dropped = true;
      continue;
    }
    out[k] = String(v);
  }
  if (dropped) out.truncated = "1";
  return out;
}

export type TxInput = Omit<
  TxInfo,
  "data_commit" | "chain_id" | "nonce" | "value" | "value_usd_cents"
> & {
  chain_id: string | bigint | number;
  nonce: string | bigint | number;
  value: string | bigint | number;
  value_usd_cents?: string | bigint | number;
};

/** Lowercase addresses/hex, decimal strings for numbers. */
export function normalizeTx(tx: TxInput): Omit<TxInfo, "data_commit"> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(tx)) {
    if (v === undefined) continue;
    out[k] =
      typeof v === "bigint" || typeof v === "number"
        ? BigInt(v).toString()
        : typeof v === "string" && v.startsWith("0x")
          ? v.toLowerCase()
          : v;
  }
  return out as Omit<TxInfo, "data_commit">;
}

/**
 * Replaces base64 binary MCP content (image/audio data, embedded resource blobs) with
 * { type, sha256, bytes } unless capture.binary = "full". Walks arrays and objects.
 */
export function hashBinaryContent(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(hashBinaryContent);
  if (value === null || typeof value !== "object") return value;
  const o = value as Record<string, unknown>;
  if ((o.type === "image" || o.type === "audio") && typeof o.data === "string") {
    const bytes = Buffer.from(o.data, "base64");
    return {
      type: o.type,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
      ...(typeof o.mimeType === "string" ? { mimeType: o.mimeType } : {}),
    };
  }
  if (typeof o.blob === "string") {
    const bytes = Buffer.from(o.blob, "base64");
    const { blob: _, ...rest } = o;
    return {
      ...rest,
      blob_sha256: createHash("sha256").update(bytes).digest("hex"),
      blob_bytes: bytes.length,
    };
  }
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, hashBinaryContent(v)]));
}
