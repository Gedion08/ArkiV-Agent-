// L6 §6 alert engine, the raising side: dedupe by (org, dedupe_key), repeats count, a resolved or expired
// suppressed alert reopens, every state change goes to alert_events and through afr_route_alert (migration
// v8) into deliveries for the API's notifier. Subjects and evidence carry ids, hashes and seqs only, never
// plaintext (W10).
import type { Pool } from "pg";
import type { Hex } from "viem";

export type AlertType =
  | "UNLOGGED_TX"
  | "UNEXPLAINED_OUTFLOW"
  | "SEQ_GAP"
  | "BROKEN_CHAIN"
  | "EQUIVOCATION"
  | "DELEGATION_MISUSE"
  | "RECORDED_GAP"
  | "RECORDER_SILENT"
  | "ANCHOR_LAG"
  | "POLICY_BREACH"
  | "UNAPPROVED_HIGH_VALUE"
  | "POLICY_BLOCK"
  | "INTENT_NOT_MINED";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Resolution = "fixed" | "false_positive" | "reorged" | "late_intent" | "expected";

/** L6 §5 table; UNLOGGED_TX is the product's core signal, so it pages (critical). */
export const ALERT_SEVERITY: Record<AlertType, Severity> = {
  UNLOGGED_TX: "critical",
  UNEXPLAINED_OUTFLOW: "high",
  SEQ_GAP: "high",
  BROKEN_CHAIN: "critical",
  EQUIVOCATION: "critical",
  DELEGATION_MISUSE: "critical",
  RECORDED_GAP: "medium",
  RECORDER_SILENT: "high",
  ANCHOR_LAG: "medium",
  POLICY_BREACH: "high",
  UNAPPROVED_HIGH_VALUE: "medium",
  POLICY_BLOCK: "info",
  INTENT_NOT_MINED: "info",
};

export interface AlertSubject {
  chain_id?: number;
  tx_hash?: Hex;
  seq_from?: string;
  seq_to?: string;
  address?: Hex;
  batch_key?: Hex;
}
export interface AlertEvidence {
  last_records?: { seq: string; hash: Hex }[];
  explorer_url?: string;
  /** Codes, hex and decimals only (no spaces), so prose can't ride along. */
  details?: Record<string, string>;
}
export interface AlertInput {
  /** agents.id */
  agentId: string;
  lane?: number;
  type: AlertType;
  dedupeKey: string;
  subject: AlertSubject;
  evidence?: AlertEvidence;
}

export interface AlertSink {
  raise(a: AlertInput): Promise<void>;
  /** Auto-resolution (reorged, late_intent, fixed); a no-op when there's no unresolved alert. */
  resolve(agentId: string, dedupeKey: string, resolution: Resolution): Promise<void>;
}

const EXPLORERS: Record<string, string> = {
  "8453": "https://basescan.org/tx/",
  "84532": "https://sepolia.basescan.org/tx/",
};
export const explorerUrl = (chainId: bigint, tx: Hex) => {
  const base = EXPLORERS[chainId.toString()];
  return base ? `${base}${tx}` : undefined;
};

/** Tests: what was raised and resolved, deduped like the table. */
export class MemoryAlerts implements AlertSink {
  readonly alerts = new Map<
    string,
    AlertInput & { count: number; status: "open" | "resolved"; resolution?: Resolution }
  >();

  async raise(a: AlertInput) {
    const cur = this.alerts.get(a.dedupeKey);
    if (!cur) this.alerts.set(a.dedupeKey, { ...a, count: 1, status: "open" });
    else Object.assign(cur, { count: cur.count + 1, status: "open", evidence: a.evidence });
  }

  async resolve(_agentId: string, dedupeKey: string, resolution: Resolution) {
    const cur = this.alerts.get(dedupeKey);
    if (cur && cur.status !== "resolved") Object.assign(cur, { status: "resolved", resolution });
  }

  open(type?: AlertType) {
    return [...this.alerts.values()].filter(
      (a) => a.status === "open" && (!type || a.type === type),
    );
  }
}

const ACTOR = "watcher";

export class PgAlerts implements AlertSink {
  constructor(readonly pool: Pool) {}

  async raise(a: AlertInput) {
    await this.#tx(async (q) => {
      const org = (
        await q.query<{ org_id: string }>("SELECT org_id FROM agents WHERE id = $1", [a.agentId])
      ).rows[0]?.org_id;
      if (!org) return;
      const evidence = a.evidence ?? {};
      const ins = (
        await q.query<{ id: string }>(
          `INSERT INTO alerts (org_id, agent_id, lane, type, severity, dedupe_key, subject, evidence)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (org_id, dedupe_key) DO NOTHING RETURNING id`,
          [
            org,
            a.agentId,
            a.lane ?? null,
            a.type,
            ALERT_SEVERITY[a.type],
            a.dedupeKey,
            a.subject,
            evidence,
          ],
        )
      ).rows[0];
      if (ins) return this.#changed(q, org, ins.id, "opened", "alert.opened", {});
      const cur = (
        await q.query<{ id: string; reopen: boolean }>(
          `SELECT id, status = 'resolved' OR (status = 'suppressed' AND suppressed_until <= now()) AS reopen
             FROM alerts WHERE org_id = $1 AND dedupe_key = $2 FOR UPDATE`,
          [org, a.dedupeKey],
        )
      ).rows[0];
      if (!cur) return;
      await q.query(
        `UPDATE alerts SET count = count + 1, last_seen_at = now(), evidence = $2,
           status = CASE WHEN $3 THEN 'open' ELSE status END,
           resolution = CASE WHEN $3 THEN NULL ELSE resolution END,
           suppressed_until = CASE WHEN $3 THEN NULL ELSE suppressed_until END
         WHERE id = $1`,
        [cur.id, evidence, cur.reopen],
      );
      if (cur.reopen) await this.#changed(q, org, cur.id, "reopened", "alert.opened", {});
    });
  }

  async resolve(agentId: string, dedupeKey: string, resolution: Resolution) {
    await this.#tx(async (q) => {
      const r = (
        await q.query<{ id: string; org_id: string }>(
          `UPDATE alerts SET status = 'resolved', resolution = $3
            WHERE org_id = (SELECT org_id FROM agents WHERE id = $1) AND dedupe_key = $2 AND status <> 'resolved'
            RETURNING id, org_id`,
          [agentId, dedupeKey, resolution],
        )
      ).rows[0];
      if (r) await this.#changed(q, r.org_id, r.id, "resolved", "alert.resolved", { resolution });
    });
  }

  async #changed(
    q: Pick<Pool, "query">,
    org: string,
    id: string,
    kind: string,
    event: string,
    data: Record<string, string>,
  ) {
    await q.query(
      "INSERT INTO alert_events (org_id, alert_id, kind, actor, data) VALUES ($1, $2, $3, $4, $5)",
      [org, id, kind, ACTOR, data],
    );
    await q.query("SELECT afr_route_alert($1, $2)", [id, event]);
  }

  async #tx(fn: (q: Pick<Pool, "query">) => Promise<void>) {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      await fn(c);
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
}
