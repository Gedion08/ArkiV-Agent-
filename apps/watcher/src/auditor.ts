// L6 §5 log auditor (P4-05). Per lane, from a cursor (next seq, last chain root), over the public sections of
// the lane's Arkiv batches: SEQ_GAP, BROKEN_CHAIN (prev root, Merkle root, record sigs, chain root; the ct hash
// is checked by decodeFrame), EQUIVOCATION, DELEGATION_MISUSE and the flag alerts. Arkiv is open-write, so a
// batch counts only if its batch_sig recovers to a listed session key; a key we know of (delegated at some
// point, or registered by the recorder) signing outside its delegation is misuse, any other signer is noise.
// RECORDED_GAP needs the record types (plaintext), so the hosted auditor can't see it (L6 §5).
// Liveness (RECORDER_SILENT, ANCHOR_LAG) comes from agent_lanes and checkpoints in Postgres.
import {
  agentKey as agentKeyOf,
  batchRoot,
  chainRoot,
  LIMITS,
  recoverRecordSigner,
} from "@afr/core";
import { type BatchEntity, type EvidenceStore, listBatches } from "@afr/store";
import { type DelegationSet, type IdentityReader, loadDelegations } from "@afr/verifier";
import type { Pool } from "pg";
import type { Hex } from "viem";
import type { AlertEvidence, AlertSink, AlertType } from "./alerts.js";
import type { AuditDb, ReconcileDb } from "./db.js";
import { arkivTime, authenticBatch, delegatedAt } from "./reconcile.js";

/** A later batch must be this old (Arkiv time) before the missing range counts as a gap, not in flight. */
export const GAP_WAIT_S = 300n;
/** Seq ranges per pass, so a first run over a long lane doesn't hold it all in memory. */
const MAX_GROUPS = 500;

export interface AuditOptions {
  db: AuditDb & Pick<ReconcileDb, "isSessionKey">;
  store: EvidenceStore;
  identity: IdentityReader;
  alerts: AlertSink;
  /** agents.id (uuid) */
  agentId: string;
  /** The ERC-8004 agent id. */
  agent: string;
  lane: number;
  writers?: Hex[];
}

type Authentic = NonNullable<Awaited<ReturnType<typeof authenticBatch>>>;

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** Audits the lane from its cursor; returns how many seq ranges were checked. */
export async function auditLane(o: AuditOptions): Promise<number> {
  const ak = agentKeyOf(o.agent);
  let { next, root } = await o.db.auditCursor(o.agentId, o.lane);
  let head: { block: bigint; timestamp: number } | undefined;
  let ds: DelegationSet | undefined;
  const raise = (
    type: AlertType,
    key: string,
    b: BatchEntity,
    a: Authentic,
    ev: AlertEvidence = {},
  ) =>
    o.alerts.raise({
      agentId: o.agentId,
      lane: o.lane,
      type,
      dedupeKey: `${type}:${o.agentId}:${o.lane}:${key}`,
      subject: { seq_from: a.pub.seq_from, seq_to: a.pub.seq_to, batch_key: b.ref.key },
      evidence: {
        last_records: a.pub.records.slice(-3).map((r) => ({ seq: r.seq, hash: r.hash as Hex })),
        ...ev,
      },
    });

  /** One seq_from's batches; false = stop the pass (a gap that may still be in flight). */
  const check = async (group: BatchEntity[]): Promise<boolean> => {
    const seqFrom = (group[0] as BatchEntity).attrs.seq_from;
    head ??= await o.store.head();
    ds ??= await loadDelegations(o.agent, {
      store: o.store,
      identity: o.identity,
      ...(o.writers ? { writers: o.writers } : {}),
    });
    const valid: { b: BatchEntity; a: Authentic }[] = [];
    for (const b of group) {
      const a = await authenticBatch(o.agent, ak, b);
      if (!a) continue;
      if (delegatedAt(ds, a.signer, o.lane, arkivTime(head, b))) {
        if (!valid.some((v) => sameBytes(v.b.payload, b.payload))) valid.push({ b, a });
      } else if (
        ds.delegations.has(a.signer) ||
        (await o.db.isSessionKey(o.agentId, o.lane, a.signer))
      )
        await raise("DELEGATION_MISUSE", `${seqFrom}:${a.signer}`, b, a, {
          details: {
            signer: a.signer,
            reason: ds.revokedAt.has(a.signer) ? "revoked" : "not_delegated",
          },
        });
    }
    if (!valid.length) return true; // noise only: the next range decides whether this one is missing
    if (valid.length > 1)
      await raise(
        "EQUIVOCATION",
        `${seqFrom}`,
        (valid[0] as { b: BatchEntity }).b,
        (valid[0] as { a: Authentic }).a,
        {
          details: { batches: valid.map((v) => v.b.ref.key).join(",") },
        },
      );
    const { b, a } =
      valid.find((v) => v.a.pub.prev_chain_root === root) ?? (valid[0] as (typeof valid)[0]);
    const p = a.pub;
    if (seqFrom > next) {
      if (BigInt(head.timestamp) - arkivTime(head, b) < GAP_WAIT_S) return false;
      await o.alerts.raise({
        agentId: o.agentId,
        lane: o.lane,
        type: "SEQ_GAP",
        dedupeKey: `SEQ_GAP:${o.agentId}:${o.lane}:${next}`,
        subject: {
          seq_from: next.toString(),
          seq_to: (seqFrom - 1n).toString(),
          batch_key: b.ref.key,
        },
      });
      root = null; // the missing batch's root is unknown: the link check resumes after this one
    }
    const failed: string[] = [];
    if (root !== null && p.prev_chain_root !== root) failed.push("CHAIN_BREAK");
    let merkle: Hex | undefined;
    try {
      merkle = batchRoot(p.records.map((r) => ({ seq: BigInt(r.seq), hash: r.hash as Hex })));
    } catch {}
    if (merkle !== p.batch_root) failed.push("MERKLE_MISMATCH");
    for (const r of p.records) {
      const s = await recoverRecordSigner(r.hash as Hex, r.sig as Hex).catch(() => undefined);
      if (!s || s !== p.session_keys[r.sk]?.toLowerCase()) {
        failed.push("RECORD_SIG");
        break;
      }
    }
    if (chainRoot(p.prev_chain_root as Hex, p.batch_root as Hex, BigInt(p.seq_to)) !== p.chain_root)
      failed.push("CHAIN_ROOT_MISMATCH");
    if (failed.length)
      await raise("BROKEN_CHAIN", `${seqFrom}`, b, a, { details: { checks: failed.join(",") } });
    if (p.flags?.has_unapproved_tx) await raise("UNAPPROVED_HIGH_VALUE", `${seqFrom}`, b, a);
    if (p.flags?.has_violation) await raise("POLICY_BREACH", `${seqFrom}`, b, a);
    if (p.flags?.has_block) await raise("POLICY_BLOCK", `${seqFrom}`, b, a);
    // the chain continues from what the batch claims, so one break doesn't cascade
    next = BigInt(p.seq_to) + 1n;
    root = p.chain_root as Hex;
    await o.db.setAuditCursor(o.agentId, o.lane, next, root);
    return true;
  };

  // shortcut: a range is checked once, so a fork published after the auditor passed it (or an overlapping
  // range) is only caught by the full verifier (L7); upgrade: re-scan a lookback window each pass.
  let group: BatchEntity[] = [];
  let checked = 0;
  for await (const b of listBatches(o.store, {
    agentKey: ak,
    lane: BigInt(o.lane),
    fromSeq: next,
    ...(o.writers ? { writers: o.writers } : {}),
  })) {
    if (b.attrs.seq_from < next) continue;
    if (group.length && b.attrs.seq_from !== group[0]?.attrs.seq_from) {
      if (!(await check(group)) || ++checked >= MAX_GROUPS) return checked;
      group = [];
      if (b.attrs.seq_from < next) continue;
    }
    group.push(b);
  }
  if (group.length && (await check(group))) checked++;
  return checked;
}

/**
 * RECORDER_SILENT: an active agent's lane with no batch or heartbeat for 3 × the heartbeat interval.
 * ANCHOR_LAG: a checkpoint still pending/validated after 3 × the anchor cadence. Both resolve (fixed) once
 * the condition clears.
 */
export async function auditLiveness(pool: Pool, alerts: AlertSink): Promise<void> {
  const silentS = (3 * LIMITS.HEARTBEAT_MS) / 1000;
  const lagS = LIMITS.ANCHOR_LAG_FACTOR * LIMITS.ANCHOR_CADENCE_S;
  const { rows } = await pool.query<{
    type: "RECORDER_SILENT" | "ANCHOR_LAG";
    agent_id: string;
    lane: number;
    bad: boolean;
    alerted: boolean;
    since: Date;
    seq_to: string | null;
  }>(
    `WITH l AS (
       SELECT 'RECORDER_SILENT' AS type, l.agent_id, l.lane, greatest(l.last_batch_at, l.last_heartbeat_at) AS since,
              NULL::text AS seq_to, greatest(l.last_batch_at, l.last_heartbeat_at) < now() - make_interval(secs => $1) AS bad
         FROM agent_lanes l JOIN agents a ON a.id = l.agent_id
        WHERE a.status = 'active' AND greatest(l.last_batch_at, l.last_heartbeat_at) IS NOT NULL
       UNION ALL
       SELECT 'ANCHOR_LAG', c.agent_id, c.lane, min(c.received_at), min(c.seq_to)::text,
              min(c.received_at) < now() - make_interval(secs => $2)
         FROM checkpoints c JOIN agents a ON a.id = c.agent_id
        WHERE a.status = 'active' AND c.status IN ('pending', 'validated')
        GROUP BY c.agent_id, c.lane)
     SELECT l.*, EXISTS (SELECT 1 FROM alerts x WHERE x.agent_id = l.agent_id
              AND x.dedupe_key = l.type || ':' || l.agent_id || ':' || l.lane AND x.status <> 'resolved') AS alerted
       FROM l`,
    [silentS, lagS],
  );
  // a lane whose checkpoints all anchored has no ANCHOR_LAG row any more: resolve those too
  const lagging = new Set(
    rows.filter((r) => r.type === "ANCHOR_LAG").map((r) => `${r.agent_id}:${r.lane}`),
  );
  const open = await pool.query<{ agent_id: string; dedupe_key: string }>(
    "SELECT agent_id, dedupe_key FROM alerts WHERE type = 'ANCHOR_LAG' AND status <> 'resolved'",
  );
  for (const a of open.rows)
    if (!lagging.has(a.dedupe_key.slice("ANCHOR_LAG:".length)))
      await alerts.resolve(a.agent_id, a.dedupe_key, "fixed");
  for (const r of rows) {
    const dedupeKey = `${r.type}:${r.agent_id}:${r.lane}`;
    if (r.bad)
      await alerts.raise({
        agentId: r.agent_id,
        lane: r.lane,
        type: r.type,
        dedupeKey,
        subject: r.seq_to ? { seq_to: r.seq_to } : {},
        evidence: { details: { since: r.since.toISOString() } },
      });
    else if (r.alerted) await alerts.resolve(r.agent_id, dedupeKey, "fixed");
  }
}
