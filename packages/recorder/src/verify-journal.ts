// Local journal verification (P1-16 `fr journal verify`): walks the SQLite chain, no network.
import { existsSync } from "node:fs";
import { AfrError, type Finding, verifyRecords } from "@afr/core";
import Database from "better-sqlite3";
import type { Hex } from "viem";

export interface JournalReport {
  path: string;
  agentId: string;
  lane: number;
  records: number;
  seqRange: [string, string] | null;
  sessions: { address: Hex; delegation: "signed" | "pending" }[];
  findings: Finding[];
  ok: boolean;
}

/** Read-only: opens the journal file without creating or migrating it. */
export async function verifyJournal(path: string): Promise<JournalReport> {
  if (!existsSync(path)) throw new AfrError("JOURNAL_NOT_FOUND", `no journal at ${path}`);
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    const meta = (k: string) =>
      (db.prepare("SELECT v FROM meta WHERE k = ?").get(k) as { v: string } | undefined)?.v;
    const rows = db
      .prepare("SELECT seq, header_jcs, hash, sig, session_key FROM records ORDER BY seq")
      .all() as {
      seq: number;
      header_jcs: string;
      hash: Hex;
      sig: Hex;
      session_key: Hex;
    }[];
    const findings = await verifyRecords(
      rows.map((r) => ({ header: JSON.parse(r.header_jcs), sig: r.sig, hash: r.hash })),
    );
    const sessions = (
      db.prepare("SELECT address, delegation_sig FROM session_keys ORDER BY created_at").all() as {
        address: Hex;
        delegation_sig: string;
      }[]
    ).map((s) => ({
      address: s.address,
      delegation: s.delegation_sig ? ("signed" as const) : ("pending" as const),
    }));
    return {
      path,
      agentId: meta("agent_id") ?? "?",
      lane: Number(meta("lane") ?? 0),
      records: rows.length,
      seqRange: rows.length ? [String(rows[0]?.seq), String(rows.at(-1)?.seq)] : null,
      sessions,
      findings,
      ok: !findings.some((f) => f.severity === "fail"),
    };
  } finally {
    db.close();
  }
}
