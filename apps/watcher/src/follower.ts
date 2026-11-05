// L6 §3.1 head follower for one EVM chain + the §3.2 EOA tx filter (P4-01, P4-02). Each block is checked
// against the parent hash in a ring of recent hashes; on a mismatch it walks back to the common ancestor,
// orphans what was observed above it and resumes from there. The cursor is persisted with every block, so a
// restart neither skips nor repeats one (W8).
//
// shortcut: polls eth_blockNumber (no newHeads subscription) and has no backfill for addresses added after
// the cursor passed their since_block (L6 §2); add both with the service loop.
import { AfrError } from "@afr/core";
import type { Hex } from "viem";
import type { Cursor, ObservedTx, WatchEntry, WatcherDb } from "./db.js";

/** The two RPC calls the follower needs (a viem PublicClient fits). */
export interface FollowerClient {
  getBlockNumber(args: { cacheTime: number }): Promise<bigint>;
  getBlock(args: { blockNumber: bigint; includeTransactions: true }): Promise<{
    number: bigint | null;
    hash: Hex | null;
    parentHash: Hex;
    transactions: readonly { hash: Hex; from: Hex; to: Hex | null; nonce: number }[];
  }>;
}

/** Who watches which address on one chain; reload() after LISTEN watched_changed. */
export class WatchedSet {
  #map = new Map<Hex, WatchEntry[]>();
  readonly db: WatcherDb;
  readonly chainId: bigint;
  constructor(db: WatcherDb, chainId: bigint) {
    this.db = db;
    this.chainId = chainId;
  }
  async reload() {
    this.#map = await this.db.watched(this.chainId);
  }
  get(address: Hex): WatchEntry[] {
    return this.#map.get(address.toLowerCase() as Hex) ?? [];
  }
}

export interface FollowerOptions {
  chainId: bigint;
  client: FollowerClient;
  db: WatcherDb;
  watched: WatchedSet;
  /** First block to process when there's no cursor yet (default: the current head). */
  startBlock?: bigint;
  /** Blocks per tick, so one tick stays short after downtime. */
  maxBlocks?: number;
  ringSize?: number;
  onObserved?: (txs: ObservedTx[]) => void | Promise<void>;
  onOrphaned?: (txs: ObservedTx[]) => void | Promise<void>;
}

export interface TickResult {
  head: bigint;
  processed: number;
  /** Common ancestor of each reorg handled in this tick. */
  reorgs: bigint[];
}

const ZERO = `0x${"00".repeat(32)}` as Hex;

export class HeadFollower {
  readonly o: Required<Pick<FollowerOptions, "maxBlocks" | "ringSize">> & FollowerOptions;
  #cur: Cursor | undefined;

  constructor(o: FollowerOptions) {
    this.o = { maxBlocks: 100, ringSize: 256, ...o };
  }

  async #block(n: bigint) {
    const b = await this.o.client.getBlock({ blockNumber: n, includeTransactions: true });
    if (b.hash === null || b.number === null) throw new AfrError("BLOCK_PENDING", `block ${n}`);
    return b as typeof b & { hash: Hex; number: bigint };
  }

  async #start(head: bigint): Promise<Cursor> {
    const from = this.o.startBlock ?? head;
    // the cursor sits just below the first block to process; block -1 has no hash to check against
    if (from === 0n) return { number: -1n, hash: ZERO, ring: [] };
    const p = await this.#block(from - 1n);
    return { number: p.number, hash: p.hash, ring: [] };
  }

  async tick(): Promise<TickResult> {
    const { chainId, db, client } = this.o;
    // cacheTime 0: viem otherwise reuses the head for a polling interval (4 s), delaying every alert
    const head = await client.getBlockNumber({ cacheTime: 0 });
    this.#cur ??= (await db.cursor(chainId)) ?? (await this.#start(head));
    const res: TickResult = { head, processed: 0, reorgs: [] };
    while (this.#cur.number < head && res.processed < this.o.maxBlocks) {
      const cur: Cursor = this.#cur;
      const blk = await this.#block(cur.number + 1n);
      if (cur.number >= 0n && blk.parentHash !== cur.hash) {
        const ancestor = await this.#ancestor(cur);
        const orphaned = await db.rewind(chainId, ancestor);
        this.#cur = ancestor;
        res.reorgs.push(ancestor.number);
        if (orphaned.length) await this.o.onOrphaned?.(orphaned);
        continue;
      }
      const txs: ObservedTx[] = [];
      for (const t of blk.transactions) {
        const w = this.o.watched.get(t.from);
        if (w.length)
          txs.push({
            chainId,
            hash: t.hash,
            blockNumber: blk.number,
            blockHash: blk.hash,
            from: t.from.toLowerCase() as Hex,
            nonce: BigInt(t.nonce),
            to: t.to ? (t.to.toLowerCase() as Hex) : null,
            agentIds: [...new Set(w.map((e) => e.agentId))],
          });
      }
      const ring = (
        cur.number >= 0n ? [...cur.ring, [cur.number, cur.hash] as [bigint, Hex]] : []
      ).slice(-this.o.ringSize);
      const next: Cursor = { number: blk.number, hash: blk.hash, ring };
      await db.commitBlock(chainId, next, txs);
      this.#cur = next;
      res.processed++;
      if (txs.length) await this.o.onObserved?.(txs);
    }
    return res;
  }

  /** The newest block in the ring (or the cursor itself) whose hash the chain still has. */
  async #ancestor(cur: Cursor): Promise<Cursor> {
    const known: [bigint, Hex][] = [...cur.ring, [cur.number, cur.hash]];
    for (let i = known.length - 1; i >= 0; i--) {
      const [n, h] = known[i] as [bigint, Hex];
      if ((await this.#block(n)).hash === h)
        return { number: n, hash: h, ring: known.slice(Math.max(0, i - this.o.ringSize), i) };
    }
    // deeper than the ring: an operator must pick a block to resume from (never guess)
    throw new AfrError("REORG_TOO_DEEP", `no common ancestor in the last ${known.length} blocks`);
  }
}
