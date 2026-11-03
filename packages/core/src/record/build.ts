// Header/body construction (L1 §3.2–3.4) [NORMATIVE]. Salt is injected; core never generates randomness.
import { bytesToString, type Hex, keccak256, stringToBytes } from "viem";
import { COMMIT_DOMAIN, type CommitDomain, LIMITS } from "../constants.js";
import { AfrError } from "../errors.js";
import { commit } from "../hash.js";
import { jcs, jcsData } from "../jcs.js";
import { RecordHeaderV1Schema } from "./schema.js";
import type { Commitments, RecordBodyV1, RecordHeaderV1 } from "./types.js";

export type BuildInput = Omit<RecordHeaderV1, "v" | "seq" | "prev_hash">;
export interface ChainState {
  seq: bigint;
  prevHash: Hex;
}

type BodyField = keyof Commitments;
export const BODY_FIELDS: Record<BodyField, CommitDomain> = {
  args: COMMIT_DOMAIN.ARGS,
  result: COMMIT_DOMAIN.RESULT,
  context: COMMIT_DOMAIN.CONTEXT,
  output: COMMIT_DOMAIN.OUTPUT,
  calldata: COMMIT_DOMAIN.CALLDATA,
};

function dropUndefined(v: unknown): unknown {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = dropUndefined(x);
  return out;
}

/** Issue paths and messages only: never echo input values. */
function describe(issues: readonly { path: readonly PropertyKey[]; message: string }[]): string {
  return issues.map((i) => `${i.path.map(String).join(".") || "<root>"}: ${i.message}`).join("; ");
}

/** Validates a header (schema + per-type fields + size). Returns the NFC-normalised header. */
export function validateHeader(raw: unknown): RecordHeaderV1 {
  const r = RecordHeaderV1Schema.safeParse(dropUndefined(raw));
  if (!r.success) throw new AfrError("HEADER_INVALID", describe(r.error.issues));
  const text = jcs(r.data);
  if (stringToBytes(text).length > LIMITS.MAX_HEADER_BYTES) {
    throw new AfrError("HEADER_TOO_LARGE", `header exceeds ${LIMITS.MAX_HEADER_BYTES} bytes`);
  }
  return JSON.parse(text) as RecordHeaderV1;
}

export function buildHeader(input: BuildInput, chain: ChainState): RecordHeaderV1 {
  return validateHeader({ v: 1, ...input, seq: chain.seq.toString(), prev_hash: chain.prevHash });
}

/** record_hash = keccak256(utf8(JCS(header))). */
export function hashHeader(h: RecordHeaderV1): Hex {
  return keccak256(stringToBytes(jcs(h)));
}

export interface BodyParts {
  args?: unknown;
  result?: unknown;
  context?: unknown;
  output?: unknown;
  calldata?: Hex;
  /** Redaction already applied by the recorder (L2 §8); listed here so verifiers can report it. */
  redacted?: { field: string; path: string; reason: string }[];
}

function truncateUtf8(s: string, maxBytes: number): string {
  const bytes = stringToBytes(s);
  if (bytes.length <= maxBytes) return s;
  // a code point split at the cut decodes to U+FFFD; drop it
  return bytesToString(bytes.slice(0, maxBytes)).replace(/�+$/u, "");
}

/**
 * Builds the body and the header commitments. Commitments always cover the FULL value;
 * parts whose JCS exceeds maxBytes are stored truncated (as a JCS-text prefix, or a hex prefix
 * for calldata) and listed in `truncated[]`.
 */
export function buildBody(
  parts: BodyParts,
  salt: Hex,
  opts: { maxBytes: number } = { maxBytes: LIMITS.MAX_BODY_BYTES_DEFAULT },
): { body: RecordBodyV1; commit: Commitments } {
  const body: RecordBodyV1 = { salt };
  const commitments: Commitments = {};
  const truncated: NonNullable<RecordBodyV1["truncated"]> = [];
  for (const [field, domain] of Object.entries(BODY_FIELDS) as [BodyField, CommitDomain][]) {
    const value = parts[field];
    if (value === undefined) continue;
    commitments[field] = commit(domain, value, salt);
    const text = jcsData(value);
    const size = stringToBytes(text).length;
    if (size <= opts.maxBytes) {
      body[field] = value as never;
      continue;
    }
    truncated.push({ field, original_hash: keccak256(stringToBytes(text)), original_bytes: size });
    body[field] =
      field === "calldata"
        ? ((value as string).slice(0, 2 + 2 * Math.floor((opts.maxBytes - 2) / 2)) as never)
        : (truncateUtf8(text, opts.maxBytes) as never);
  }
  if (truncated.length) body.truncated = truncated;
  if (parts.redacted?.length) body.redacted = parts.redacted;
  return { body, commit: commitments };
}

/** Recomputes commitments from a body, skipping truncated fields (not checkable). */
export function commitmentsFor(body: RecordBodyV1): Commitments {
  const skip = new Set(body.truncated?.map((t) => t.field));
  const out: Commitments = {};
  for (const [field, domain] of Object.entries(BODY_FIELDS) as [BodyField, CommitDomain][]) {
    const value = body[field];
    if (value === undefined || skip.has(field)) continue;
    out[field] = commit(domain, value, body.salt as Hex);
  }
  return out;
}
