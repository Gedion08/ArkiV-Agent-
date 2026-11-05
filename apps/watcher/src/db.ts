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

type Status = "seen" | "orphaned";

export class MemoryWatcherDb implements WatcherDb {
  readonly cursors = new Map<bigint, Cursor>();
  readonly observed = new Map<string, ObservedTx & { status: Status }>();
  readonly watches: { chainId: bigint; address: Hex; entry: WatchEntry }[] = [];
  /** Tests: commitBlock calls, to check nothing is processed twice. */
  readonly commits: bigint[] = [];

  async cursor(chainId: bigint) {
    const c = this.cursors.get(chainId);
    return c && { ...c, ring: [...c.ring] };
  }

  async commitBlock(chainId: bigint, cursor: Cursor, txs: ObservedTx[]) {
    for (const t of txs) this.observed.set(`${chainId}:${t.hash}`, { ...t, status: "seen" });
    this.cursors.set(chainId, { ...cursor, ring: [...cursor.ring] });
    this.commits.push(cursor.number);
  }

  async rewind(chainId: bigint, cursor: Cursor) {
    const out: ObservedTx[] = [];
    for (const t of this.observed.values())
      if (t.chainId === chainId && t.blockNumber > cursor.number && t.status === "seen") {
        t.status = "orphaned";
        const { status: _s, ...tx } = t;
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
}

const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");
const hex = (b: Buffer) => `0x${b.toString("hex")}` as Hex;

export class PgWatcherDb implements WatcherDb {
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
}

/**
 * LISTEN watched_changed (the migration's trigger on watched_addresses): calls `onChange` for this chain.
 * One dedicated connection; returns a function that stops listening.
 */
export async function listenWatched(
  pool: Pool,
  chainId: bigint,
  onChange: () => void,
): Promise<() => Promise<void>> {
  const c = await pool.connect();
  c.on("notification", (n) => {
    if (n.channel === "watched_changed" && n.payload === chainId.toString()) onChange();
  });
  await c.query("LISTEN watched_changed");
  return async () => {
    await c.query("UNLISTEN watched_changed").catch(() => {});
    c.release();
  };
}
