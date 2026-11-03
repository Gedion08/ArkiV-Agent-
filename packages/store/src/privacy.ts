// L3 §5 attribute privacy rules, enforced before any write.
import { AfrError, LIMITS } from "@afr/core";
import { type AfrSchemaName, SCHEMA_SPEC } from "./schemas.js";
import type { PutRequest } from "./types.js";

export type PrivacyLevel = 0 | 1 | 2;

const LEVEL0 = [
  "agent_key",
  "lane",
  "seq_from",
  "seq_to",
  "chain_root",
  "prev_chain_root",
  "batch_root",
  "session_key",
  "epoch_id",
  "record_count",
  "privacy",
] as const;
const LEVEL1 = ["has_tx", "has_block", "has_unapproved_tx", "has_violation"] as const;

/** Batch attributes allowed at each privacy level (the payload column `frame` is always written). */
export const BATCH_ATTR_ALLOWLIST: Record<PrivacyLevel, ReadonlySet<string>> = {
  0: new Set(LEVEL0),
  1: new Set([...LEVEL0, ...LEVEL1]),
  2: new Set([...LEVEL0, ...LEVEL1]),
};

const fail = (code: string, msg: string) => {
  throw new AfrError(code, msg);
};

const HEX32 = /^0x[0-9a-f]{64}$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const U64_MAX = 2n ** 64n - 1n;

/** Type, presence and value checks against the schema spec (str ≤ 128 B, u64 range, addr shape). */
export function assertAttrs<S extends AfrSchemaName>(schema: S, attrs: Record<string, unknown>) {
  const spec = SCHEMA_SPEC[schema]?.attrs as
    | Record<string, { type: string; optional?: true }>
    | undefined;
  if (!spec) fail("SCHEMA_NOT_ALLOWED", `unknown schema ${String(schema)}`);
  for (const [name, a] of Object.entries(spec as object) as [
    string,
    { type: string; optional?: true },
  ][]) {
    const v = attrs[name];
    if (v === undefined) {
      if (!a.optional) fail("ATTR_INVALID", `${schema}.${name} is required`);
      continue;
    }
    const ok =
      a.type === "str"
        ? typeof v === "string" && new TextEncoder().encode(v).length <= 128
        : a.type === "u64"
          ? typeof v === "bigint" && v >= 0n && v <= U64_MAX
          : a.type === "addr"
            ? typeof v === "string" && ADDR.test(v)
            : typeof v === "boolean";
    if (!ok) fail("ATTR_INVALID", `${schema}.${name} is not a valid ${a.type}`);
  }
  for (const name of Object.keys(attrs))
    if (!(spec as object)[name as never])
      fail("ATTR_INVALID", `${schema} has no attribute ${name}`);
  // hex roots/keys are lowercase (L1 conventions); a mixed-case 64-hex would not query-match
  for (const k of ["agent_key", "chain_root", "prev_chain_root", "batch_root"])
    if (
      typeof attrs[k] === "string" &&
      /^0x[0-9a-fA-F]{64}$/.test(attrs[k] as string) &&
      !HEX32.test(attrs[k] as string)
    )
      fail("ATTR_INVALID", `${schema}.${k} must be lowercase hex`);
}

/** Privacy allowlist (C9): no attribute beyond the level's allowlist; `privacy` must equal the level. */
export function assertPrivacy(req: Pick<PutRequest, "schema" | "attrs">, level: PrivacyLevel) {
  if (req.schema === "afr.action.v1" && level !== 2)
    fail("SCHEMA_NOT_ALLOWED", "afr.action.v1 entities exist only at privacy level 2");
  if (req.schema !== "afr.batch.v1") return;
  const attrs = req.attrs as Record<string, unknown>;
  for (const name of Object.keys(attrs))
    if (!BATCH_ATTR_ALLOWLIST[level].has(name))
      fail("PRIVACY_ATTR", `attribute ${name} is not allowed at privacy level ${level}`);
  if (attrs.privacy !== BigInt(level))
    fail("PRIVACY_ATTR", `privacy attr must equal level ${level}`);
}

/** Every pre-write check shared by all stores. */
export function validatePut(req: PutRequest, level: PrivacyLevel) {
  assertAttrs(req.schema, req.attrs as Record<string, unknown>);
  assertPrivacy(req, level);
  if (req.payload.length > LIMITS.BATCH_MAX_FRAME_BYTES)
    fail(
      "PAYLOAD_TOO_LARGE",
      `payload ${req.payload.length} B > ${LIMITS.BATCH_MAX_FRAME_BYTES} B`,
    );
  if ("days" in req.expiresAt && !(Number.isInteger(req.expiresAt.days) && req.expiresAt.days > 0))
    fail("EXPIRY_INVALID", "expiresAt.days must be a positive integer");
}
