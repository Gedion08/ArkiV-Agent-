// Watcher state (L6 §2, §3.1): chain_cursors, observed_txs and the watched set, in the API schema (ARCHITECTURE
// §8 table list; migration v5). Memory for tests; Postgres in production. The watcher connects as the table
// owner, so RLS doesn't apply.
import type { Pool } from "pg";
import type { Hex } from "viem";

export type WatchKind = "eoa" | "smart_account" | "safe" | "session_key";

export interface WatchEntry {
  orgId: string;
  agentId: string;
  kind: WatchKind;
  sinceBlock?: bigint;
}

/** The last processed block plus the hashes of up to `ringSize` blocks before it, oldest first. */
export interface Cursor {
  number: bigint;
  hash: Hex;
  ring: [bigint, Hex][];
}

export interface ObservedTx {
  chainId: bigint;
  hash: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  from: Hex;
  nonce: bigint;
  to: Hex | null;
  /** The agents watching `from` when the tx was seen. */
  agentIds: string[];
}

export interface WatcherDb {
  cursor(chainId: bigint): Promise<Cursor | undefined>;
  /** One block, atomically: its watched txs (re-seen after a reorg → back to 'seen') and the new cursor. */
  commitBlock(chainId: bigint, cursor: Cursor, txs: ObservedTx[]): Promise<void>;
  /** Reorg: txs above the common ancestor become 'orphaned' (returned); the cursor goes back to it. */
  rewind(chainId: bigint, cursor: Cursor): Promise<ObservedTx[]>;
  /** Lowercase address → who watches it on this chain. */
  watched(chainId: bigint): Promise<Map<Hex, WatchEntry[]>>;
}

export type MatchKind = "exact" | "replacement" | "late_intent" | "unlogged";

/** An observed tx still to decide for one of its agents: no verdict yet, or alerted ('unlogged'). */
export interface Candidate {
  tx: ObservedTx;
  agentId: string;
  /** ms */
  seenAt: number;
  match?: "unlogged";
}

export interface Commits {
  tx: Hex;
  nonce: Hex;
}

/** L6 §4: both intent sources (API tx_intents, reconciled Arkiv batches) and the per-tx verdicts. */
export interface MatcherDb {
  /** 'seen' txs on this chain observed at or after `since` (ms) that are undecided or 'unlogged'. */
  candidates(chainId: bigint, since: number): Promise<Candidate[]>;
  /** 'exact' (tx commitment) beats 'replacement' (nonce commitment only). */
  findIntent(
    agentId: string,
    chainId: bigint,
    c: Commits,
  ): Promise<"exact" | "replacement" | undefined>;
  setMatch(chainId: bigint, hash: Hex, agentId: string, kind: MatchKind, c: Commits): Promise<void>;
  /** API intents received before `before` (ms) that no tx matched; each is returned once. */
  notMined(
    chainId: bigint,
    before: number,
  ): Promise<{ agentId: string; lane: number; seq: bigint }[]>;
}

/** L6 §4.1 batch reconciliation state. */
export interface ReconcileDb {
  /** The next seq_from expected on this lane (0 at first). */
  reconcileCursor(agentId: string, lane: number): Promise<bigint>;
  /** A valid batch's commitments plus the cursor moved past it, atomically. */
  addBatchCommitments(
    agentId: string,
    lane: number,
    seqTo: bigint,
    tx: readonly Hex[],
    nonce: readonly Hex[],
  ): Promise<void>;
  /** The recorder registered this session key for the lane (POST /v1/recorder/delegations) and it isn't revoked. */
  isSessionKey(agentId: string, lane: number, address: Hex): Promise<boolean>;
}

type Status = "seen" | "orphaned";

export interface MemoryIntent {
  agentId: string;
  lane: number;
  seq: bigint;
  chainId: bigint;
  txCommit?: Hex;
  nonceCommit: Hex;
  receivedAt: number;
  notMined?: boolean;
}

export class MemoryWatcherDb implements WatcherDb, MatcherDb, ReconcileDb {
  /** Tests move this clock; it stamps seenAt like Postgres' now(). */
  now: () => number = Date.now;
  readonly cursors = new Map<bigint, Cursor>();
  readonly observed = new Map<string, ObservedTx & { status: Status; seenAt: number }>();
  readonly intents: MemoryIntent[] = [];
  readonly batchCommits: { agentId: string; kind: "tx" | "nonce"; commitment: Hex }[] = [];
  readonly reconcileCursors = new Map<string, bigint>();
  readonly sessionKeys: { agentId: string; lane: number; address: Hex }[] = [];
  readonly matches = new Map<string, { kind: MatchKind; agentId: string } & Commits>();
  readonly watches: { chainId: bigint; address: Hex; entry: WatchEntry }[] = [];
  /** Tests: commitBlock calls, to check nothing is processed twice. */
  readonly commits: bigint[] = [];

  async cursor(chainId: bigint) {
    const c = this.cursors.get(chainId);
    return c && { ...c, ring: [...c.ring] };
  }

  async commitBlock(chainId: bigint, cursor: Cursor, txs: ObservedTx[]) {
    for (const t of txs)
      this.observed.set(`${chainId}:${t.hash}`, { ...t, status: "seen", seenAt: this.now() });
    this.cursors.set(chainId, { ...cursor, ring: [...cursor.ring] });
    this.commits.push(cursor.number);
  }

  async rewind(chainId: bigint, cursor: Cursor) {
    const out: ObservedTx[] = [];
    for (const t of this.observed.values())
      if (t.chainId === chainId && t.blockNumber > cursor.number && t.status === "seen") {
        t.status = "orphaned";
        const { status: _s, seenAt: _t, ...tx } = t;
        out.push(tx);
      }
    this.cursors.set(chainId, { ...cursor, ring: [...cursor.ring] });
    return out;
  }

  async watched(chainId: bigint) {
    const m = new Map<Hex, WatchEntry[]>();
    for (const w of this.watches)
      if (w.chainId === chainId) {
        const a = w.address.toLowerCase() as Hex;
        m.set(a, [...(m.get(a) ?? []), w.entry]);
      }
    return m;
  }

  async candidates(chainId: bigint, since: number) {
    const out: Candidate[] = [];
    for (const { status, seenAt, ...tx } of this.observed.values()) {
      if (tx.chainId !== chainId || status !== "seen" || seenAt < since) continue;
      for (const agentId of tx.agentIds) {
        const m = this.matches.get(`${chainId}:${tx.hash}:${agentId}`)?.kind;
        if (!m) out.push({ tx, agentId, seenAt });
        else if (m === "unlogged") out.push({ tx, agentId, seenAt, match: m });
      }
    }
    return out;
  }

  async findIntent(agentId: string, chainId: bigint, c: Commits) {
    const mine = this.intents.filter((i) => i.agentId === agentId && i.chainId === chainId);
    const batch = this.batchCommits.filter((b) => b.agentId === agentId);
    if (
      mine.some((i) => i.txCommit === c.tx) ||
      batch.some((b) => b.kind === "tx" && b.commitment === c.tx)
    )
      return "exact" as const;
    if (
      mine.some((i) => i.nonceCommit === c.nonce) ||
      batch.some((b) => b.kind === "nonce" && b.commitment === c.nonce)
    )
      return "replacement" as const;
    return undefined;
  }

  async setMatch(chainId: bigint, hash: Hex, agentId: string, kind: MatchKind, c: Commits) {
    this.matches.set(`${chainId}:${hash}:${agentId}`, { kind, agentId, ...c });
  }

  async notMined(chainId: bigint, before: number) {
    const matched = [...this.matches.values()];
    return this.intents
      .filter(
        (i) =>
          i.chainId === chainId &&
          !i.notMined &&
          i.receivedAt < before &&
          !matched.some(
            (m) => m.agentId === i.agentId && (m.tx === i.txCommit || m.nonce === i.nonceCommit),
          ),
      )
      .map((i) => {
        i.notMined = true;
        return { agentId: i.agentId, lane: i.lane, seq: i.seq };
      });
  }

  async reconcileCursor(agentId: string, lane: number) {
    return this.reconcileCursors.get(`${agentId}:${lane}`) ?? 0n;
  }

  async addBatchCommitments(
    agentId: string,
    lane: number,
    seqTo: bigint,
    tx: readonly Hex[],
    nonce: readonly Hex[],
  ) {
    for (const [kind, list] of [
      ["tx", tx],
      ["nonce", nonce],
    ] as const)
      for (const commitment of list)
        if (
          !this.batchCommits.some(
            (b) => b.agentId === agentId && b.kind === kind && b.commitment === commitment,
          )
        )
          this.batchCommits.push({ agentId, kind, commitment });
    this.reconcileCursors.set(`${agentId}:${lane}`, seqTo + 1n);
  }

  async isSessionKey(agentId: string, lane: number, address: Hex) {
    const a = address.toLowerCase();
    return this.sessionKeys.some(
      (k) => k.agentId === agentId && k.lane === lane && k.address.toLowerCase() === a,
    );
  }
}

const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");
const hex = (b: Buffer) => `0x${b.toString("hex")}` as Hex;

export class PgWatcherDb implements WatcherDb, MatcherDb, ReconcileDb {
  readonly pool: Pool;
  constructor(pool: Pool) {
    this.pool = pool;
  }

  async cursor(chainId: bigint): Promise<Cursor | undefined> {
    const { rows } = await this.pool.query<{ n: string; h: Buffer; ring: [string, Hex][] }>(
      "SELECT block_number::text AS n, block_hash AS h, ring FROM chain_cursors WHERE chain_id = $1",
      [chainId.toString()],
    );
    const r = rows[0];
    return (
      r && { number: BigInt(r.n), hash: hex(r.h), ring: r.ring.map(([n, h]) => [BigInt(n), h]) }
    );
  }

  async #saveCursor(q: Pick<Pool, "query">, chainId: bigint, c: Cursor) {
    await q.query(
      `INSERT INTO chain_cursors (chain_id, block_number, block_hash, ring, updated_at) VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (chain_id) DO UPDATE SET block_number = excluded.block_number, block_hash = excluded.block_hash,
         ring = excluded.ring, updated_at = now()`,
      [
        chainId.toString(),
        c.number.toString(),
        buf(c.hash),
        JSON.stringify(c.ring.map(([n, h]) => [n.toString(), h])),
      ],
    );
  }

  async #tx<T>(fn: (q: Pick<Pool, "query">) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }

  commitBlock(chainId: bigint, cursor: Cursor, txs: ObservedTx[]) {
    return this.#tx(async (q) => {
      for (const t of txs)
        await q.query(
          `INSERT INTO observed_txs (chain_id, tx_hash, block_number, block_hash, from_addr, nonce, to_addr, agent_ids)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::uuid[])
           ON CONFLICT (chain_id, tx_hash) DO UPDATE SET block_number = excluded.block_number,
             block_hash = excluded.block_hash, agent_ids = excluded.agent_ids, status = 'seen', seen_at = now()`,
          [
            chainId.toString(),
            buf(t.hash),
            t.blockNumber.toString(),
            buf(t.blockHash),
            buf(t.from),
            t.nonce.toString(),
            t.to ? buf(t.to) : null,
            t.agentIds,
          ],
        );
      await this.#saveCursor(q, chainId, cursor);
    });
  }

  rewind(chainId: bigint, cursor: Cursor) {
    return this.#tx(async (q) => {
      const { rows } = await q.query<{
        tx_hash: Buffer;
        block_number: string;
        block_hash: Buffer;
        from_addr: Buffer;
        nonce: string;
        to_addr: Buffer | null;
        agent_ids: string[];
      }>(
        `UPDATE observed_txs SET status = 'orphaned' WHERE chain_id = $1 AND block_number > $2 AND status = 'seen'
         RETURNING tx_hash, block_number::text, block_hash, from_addr, nonce::text, to_addr, agent_ids`,
        [chainId.toString(), cursor.number.toString()],
      );
      await this.#saveCursor(q, chainId, cursor);
      return rows.map((r) => ({
        chainId,
        hash: hex(r.tx_hash),
        blockNumber: BigInt(r.block_number),
        blockHash: hex(r.block_hash),
        from: hex(r.from_addr),
        nonce: BigInt(r.nonce),
        to: r.to_addr ? hex(r.to_addr) : null,
        agentIds: r.agent_ids,
      }));
    });
  }

  async watched(chainId: bigint) {
    const { rows } = await this.pool.query<{
      address: Buffer;
      org_id: string;
      agent_id: string;
      kind: WatchKind;
      since_block: string | null;
    }>(
      "SELECT address, org_id, agent_id, kind, since_block::text FROM watched_addresses WHERE chain_id = $1",
      [chainId.toString()],
    );
    const m = new Map<Hex, WatchEntry[]>();
    for (const r of rows) {
      const a = hex(r.address);
      const e: WatchEntry = {
        orgId: r.org_id,
        agentId: r.agent_id,
        kind: r.kind,
        ...(r.since_block !== null ? { sinceBlock: BigInt(r.since_block) } : {}),
      };
      m.set(a, [...(m.get(a) ?? []), e]);
    }
    return m;
  }

  async candidates(chainId: bigint, since: number) {
    const { rows } = await this.pool.query<{
      tx_hash: Buffer;
      block_number: string;
      block_hash: Buffer;
      from_addr: Buffer;
      nonce: string;
      to_addr: Buffer | null;
      agent_ids: string[];
      agent_id: string;
      seen_ms: string;
      kind: "unlogged" | null;
    }>(
      `SELECT o.tx_hash, o.block_number::text, o.block_hash, o.from_addr, o.nonce::text, o.to_addr, o.agent_ids,
              a.agent_id, (extract(epoch FROM o.seen_at) * 1000)::bigint::text AS seen_ms, m.kind
         FROM observed_txs o CROSS JOIN LATERAL unnest(o.agent_ids) AS a(agent_id)
         LEFT JOIN tx_matches m ON m.chain_id = o.chain_id AND m.tx_hash = o.tx_hash AND m.agent_id = a.agent_id
        WHERE o.chain_id = $1 AND o.status = 'seen' AND o.seen_at >= to_timestamp($2::double precision / 1000)
          AND (m.kind IS NULL OR m.kind = 'unlogged')`,
      [chainId.toString(), since],
    );
    return rows.map((r) => ({
      tx: {
        chainId,
        hash: hex(r.tx_hash),
        blockNumber: BigInt(r.block_number),
        blockHash: hex(r.block_hash),
        from: hex(r.from_addr),
        nonce: BigInt(r.nonce),
        to: r.to_addr ? hex(r.to_addr) : null,
        agentIds: r.agent_ids,
      },
      agentId: r.agent_id,
      seenAt: Number(r.seen_ms),
      ...(r.kind ? { match: r.kind } : {}),
    }));
  }

  async findIntent(agentId: string, chainId: bigint, c: Commits) {
    const { rows } = await this.pool.query<{ r: number | null }>(
      `SELECT min(r) AS r FROM (
         SELECT CASE WHEN tx_commit = $3 THEN 0 ELSE 1 END AS r FROM tx_intents
          WHERE agent_id = $1 AND chain_id = $2 AND (tx_commit = $3 OR nonce_commit = $4)
         UNION ALL
         SELECT CASE WHEN kind = 'tx' THEN 0 ELSE 1 END FROM batch_commitments
          WHERE agent_id = $1 AND ((kind = 'tx' AND commitment = $3) OR (kind = 'nonce' AND commitment = $4))
       ) hits`,
      [agentId, chainId.toString(), buf(c.tx), buf(c.nonce)],
    );
    const r = rows[0]?.r;
    return r === 0 ? ("exact" as const) : r === 1 ? ("replacement" as const) : undefined;
  }

  async setMatch(chainId: bigint, hash: Hex, agentId: string, kind: MatchKind, c: Commits) {
    await this.pool.query(
      `INSERT INTO tx_matches (chain_id, tx_hash, agent_id, kind, tx_commit, nonce_commit) VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (chain_id, tx_hash, agent_id) DO UPDATE SET kind = excluded.kind, at = now()`,
      [chainId.toString(), buf(hash), agentId, kind, buf(c.tx), buf(c.nonce)],
    );
  }

  async notMined(chainId: bigint, before: number) {
    const { rows } = await this.pool.query<{ agent_id: string; lane: number; seq: string }>(
      `UPDATE tx_intents i SET not_mined_at = now()
        WHERE i.chain_id = $1 AND i.not_mined_at IS NULL AND i.received_at < to_timestamp($2::double precision / 1000)
          AND NOT EXISTS (SELECT 1 FROM tx_matches m WHERE m.agent_id = i.agent_id
                            AND (m.tx_commit = i.tx_commit OR m.nonce_commit = i.nonce_commit))
        RETURNING i.agent_id, i.lane, i.seq::text`,
      [chainId.toString(), before],
    );
    return rows.map((r) => ({ agentId: r.agent_id, lane: r.lane, seq: BigInt(r.seq) }));
  }

  async reconcileCursor(agentId: string, lane: number) {
    const { rows } = await this.pool.query<{ n: string }>(
      "SELECT next_seq::text AS n FROM reconcile_cursors WHERE agent_id = $1 AND lane = $2",
      [agentId, lane],
    );
    return BigInt(rows[0]?.n ?? 0);
  }

  addBatchCommitments(
    agentId: string,
    lane: number,
    seqTo: bigint,
    tx: readonly Hex[],
    nonce: readonly Hex[],
  ) {
    return this.#tx(async (q) => {
      for (const [kind, list] of [
        ["tx", tx],
        ["nonce", nonce],
      ] as const)
        for (const c of list)
          await q.query(
            `INSERT INTO batch_commitments (agent_id, kind, commitment, lane, seq_to) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING`,
            [agentId, kind, buf(c), lane, seqTo.toString()],
          );
      await q.query(
        `INSERT INTO reconcile_cursors (agent_id, lane, next_seq) VALUES ($1, $2, $3)
         ON CONFLICT (agent_id, lane) DO UPDATE SET next_seq = excluded.next_seq, updated_at = now()`,
        [agentId, lane, (seqTo + 1n).toString()],
      );
    });
  }

  async isSessionKey(agentId: string, lane: number, address: Hex) {
    const { rowCount } = await this.pool.query(
      "SELECT 1 FROM session_keys WHERE agent_id = $1 AND lane = $2 AND address = $3 AND revoked_at IS NULL",
      [agentId, lane, buf(address.toLowerCase() as Hex)],
    );
    return Boolean(rowCount);
  }
}

/**
 * LISTEN watched_changed (the migration's trigger on watched_addresses): calls `onChange` for this chain.
 * One dedicated connection; returns a function that stops listening.
 */
export function listenWatched(pool: Pool, chainId: bigint, onChange: () => void) {
  return listen(pool, "watched_changed", (p) => p === chainId.toString() && onChange());
}

/** LISTEN afr_intents (the API's POST /v1/recorder/intents): `onIntent(agentId)`, to sweep early. */
export function listenIntents(pool: Pool, onIntent: (agentId: string) => void) {
  return listen(pool, "afr_intents", (p) => p && onIntent(p));
}

async function listen(
  pool: Pool,
  channel: string,
  fn: (payload: string | undefined) => unknown,
): Promise<() => Promise<void>> {
  const c = await pool.connect();
  c.on("notification", (n) => {
    if (n.channel === channel) fn(n.payload);
  });
  await c.query(`LISTEN ${channel}`);
  return async () => {
    await c.query(`UNLISTEN ${channel}`).catch(() => {});
    c.release();
  };
}
