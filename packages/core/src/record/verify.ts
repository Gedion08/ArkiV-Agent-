// Header-level and chain-link verification (L1 §3–4). Codes match L7 §3.
import type { Hex } from "viem";
import { ZERO_HASH } from "../constants.js";
import type { AfrError } from "../errors.js";
import { commit } from "../hash.js";
import { recoverRecordSigner } from "../sign.js";
import { BODY_FIELDS, hashHeader, validateHeader } from "./build.js";
import type { RecordBodyV1, RecordHeaderV1 } from "./types.js";

export type FindingCode =
  | "HEADER_INVALID"
  | "HEADER_HASH"
  | "SEQ_GAP"
  | "CHAIN_BREAK"
  | "RECORD_SIG"
  | "COMMIT_MISMATCH"
  | "TRUNCATED"
  | "REDACTED"
  | "GAP";

/** A gap record at to_seq + 1 covering [expectSeq, to_seq]. */
function coversGap(h: RecordHeaderV1, expectSeq: bigint): boolean {
  const from = h.meta?.from_seq;
  const to = h.meta?.to_seq;
  if (!from || !to || !/^(0|[1-9][0-9]*)$/.test(from) || !/^(0|[1-9][0-9]*)$/.test(to))
    return false;
  return (
    BigInt(from) === expectSeq && BigInt(to) >= BigInt(from) && BigInt(h.seq) === BigInt(to) + 1n
  );
}

export interface Finding {
  code: FindingCode;
  severity: "fail" | "info";
  index: number;
  seq?: string;
  detail?: string;
}

export interface ChainStart {
  seq: bigint;
  prevHash: Hex;
}

const GENESIS: ChainStart = { seq: 0n, prevHash: ZERO_HASH };

/**
 * Checks schema, (agent, lane) consistency, seq continuity and prev_hash links. Synchronous; no signatures.
 * Returns the validated headers' hashes alongside findings so callers don't rehash.
 */
export function verifyLinks(
  headers: readonly unknown[],
  start: ChainStart = GENESIS,
): { findings: Finding[]; hashes: (Hex | undefined)[] } {
  const findings: Finding[] = [];
  const hashes: (Hex | undefined)[] = [];
  // undefined after an invalid header: links resync on the next valid record instead of cascading
  let expectSeq: bigint | undefined = start.seq;
  let expectPrev: Hex | undefined = start.prevHash;
  let agent: string | undefined;
  let lane: number | undefined;
  headers.forEach((raw, index) => {
    let h: RecordHeaderV1;
    try {
      h = validateHeader(raw);
    } catch (e) {
      findings.push({
        code: "HEADER_INVALID",
        severity: "fail",
        index,
        detail: (e as AfrError).message,
      });
      hashes.push(undefined);
      expectSeq = undefined;
      expectPrev = undefined;
      return;
    }
    const hash = hashHeader(h);
    hashes.push(hash);
    agent ??= h.agent_id;
    lane ??= h.lane;
    if (h.agent_id !== agent || h.lane !== lane) {
      findings.push({
        code: "HEADER_INVALID",
        severity: "fail",
        index,
        seq: h.seq,
        detail: "agent/lane changed",
      });
    }
    if (h.type === "gap" && expectSeq !== undefined && coversGap(h, expectSeq)) {
      // L2 §3.2: seqs from_seq..to_seq were reserved but never signed; the gap record sits at to_seq + 1
      findings.push({
        code: "GAP",
        severity: "info",
        index,
        seq: h.seq,
        detail: `${h.meta?.from_seq}..${h.meta?.to_seq}`,
      });
    } else if (expectSeq !== undefined && BigInt(h.seq) !== expectSeq) {
      findings.push({
        code: "SEQ_GAP",
        severity: "fail",
        index,
        seq: h.seq,
        detail: `expected ${expectSeq}`,
      });
    }
    if (expectPrev !== undefined && h.prev_hash !== expectPrev) {
      findings.push({ code: "CHAIN_BREAK", severity: "fail", index, seq: h.seq });
    }
    expectSeq = BigInt(h.seq) + 1n;
    expectPrev = hash;
  });
  return { findings, hashes };
}

export interface SignedRecord {
  header: unknown;
  sig: Hex;
  /** Claimed record hash (e.g. from a batch public section); checked against the recomputed one. */
  hash?: Hex;
}

/**
 * verifyLinks + record hash + signatures. A record must be signed by the `meta.session_key` of its
 * session's `session_start` when one is in range, and by one of `opts.signers` when given.
 */
export async function verifyRecords(
  records: readonly SignedRecord[],
  opts: { start?: ChainStart; signers?: readonly Hex[] } = {},
): Promise<Finding[]> {
  const { findings, hashes } = verifyLinks(
    records.map((r) => r.header),
    opts.start,
  );
  const sessionKeys = new Map<string, string>();
  const allowed = opts.signers?.map((s) => s.toLowerCase());
  for (const [index, r] of records.entries()) {
    const hash = hashes[index];
    if (!hash) continue;
    const h = r.header as RecordHeaderV1;
    if (r.hash !== undefined && r.hash !== hash) {
      findings.push({ code: "HEADER_HASH", severity: "fail", index, seq: h.seq });
    }
    if (h.type === "session_start" && h.meta?.session_key) {
      sessionKeys.set(h.session_id, h.meta.session_key.toLowerCase());
    }
    let signer: string;
    try {
      signer = await recoverRecordSigner(hash, r.sig);
    } catch {
      findings.push({
        code: "RECORD_SIG",
        severity: "fail",
        index,
        seq: h.seq,
        detail: "unrecoverable",
      });
      continue;
    }
    const expected = sessionKeys.get(h.session_id);
    if ((expected && signer !== expected) || (allowed && !allowed.includes(signer))) {
      findings.push({
        code: "RECORD_SIG",
        severity: "fail",
        index,
        seq: h.seq,
        detail: "unexpected signer",
      });
    }
  }
  return findings.sort((a, b) => a.index - b.index);
}

/** Recomputes header commitments from a decrypted body. */
export function verifyBody(header: RecordHeaderV1, body: RecordBodyV1, index = 0): Finding[] {
  const out: Finding[] = [];
  const truncated = new Set(body.truncated?.map((t) => t.field));
  for (const [field, domain] of Object.entries(BODY_FIELDS) as [
    keyof typeof BODY_FIELDS,
    never,
  ][]) {
    const expected = header.commit[field];
    const value = body[field];
    if (expected === undefined && value === undefined) continue;
    if (truncated.has(field)) {
      out.push({ code: "TRUNCATED", severity: "info", index, seq: header.seq, detail: field });
      continue;
    }
    if (
      expected === undefined ||
      value === undefined ||
      commit(domain, value, body.salt as Hex) !== expected
    ) {
      out.push({
        code: "COMMIT_MISMATCH",
        severity: "fail",
        index,
        seq: header.seq,
        detail: field,
      });
    }
  }
  for (const r of body.redacted ?? []) {
    out.push({
      code: "REDACTED",
      severity: "info",
      index,
      seq: header.seq,
      detail: `${r.field}${r.path}`,
    });
  }
  return out;
}
