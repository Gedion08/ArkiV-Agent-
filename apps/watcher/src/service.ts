// L6 §1 watcher service for one EVM chain: head follower (every 2 s), matcher sweep (every 5 s and on
// LISTEN afr_intents), batch reconciliation of every active lane (every 60 s). One leader per chain (pg
// advisory lock); state lives in Postgres, so a restart or failover resumes where the last leader stopped.
// Match events are logged until the alert engine (P4-06) consumes them.
import { AfrError } from "@afr/core";
import type { Logger } from "@afr/log";
import type { OrgSecrets } from "@afr/secrets";
import type { EvidenceStore } from "@afr/store";
import type { IdentityReader } from "@afr/verifier";
import type { Pool } from "pg";
import type { Hex } from "viem";
import { listen, PgWatcherDb } from "./db.js";
import { type FollowerClient, HeadFollower, WatchedSet } from "./follower.js";
import { type MatchEvent, Matcher } from "./matcher.js";
import { reconcileLane } from "./reconcile.js";

/** pg advisory lock key base; the chain id is added, so each chain has one leader. */
export const WATCHER_LOCK_KEY = 0xafa0c5n << 32n;

export interface WatcherServiceOptions {
  pool: Pool;
  chainId: bigint;
  client: FollowerClient;
  /** Arkiv, read-only (batches, delegations, revocations). */
  store: EvidenceStore;
  identity: IdentityReader;
  secrets: OrgSecrets;
  signal: AbortSignal;
  logger?: Logger;
  /** First block when there's no cursor yet (default: the head). */
  startBlock?: bigint;
  followMs?: number;
  sweepMs?: number;
  reconcileMs?: number;
  retryLockMs?: number;
  now?: () => number;
  onEvent?: (e: MatchEvent) => void | Promise<void>;
}

/** The agent's watch keys from watch_keys (current, then the pre-rotation one), opened with the agent key as AAD. */
export function pgWatchKeys(pool: Pool, secrets: OrgSecrets) {
  return async (agentId: string): Promise<Uint8Array[]> => {
    const r = (
      await pool.query<{ org_id: string; agent_key: Buffer; cur: Buffer; prev: Buffer | null }>(
        `SELECT a.org_id, a.agent_key, w.kms_ciphertext AS cur, w.prev_kms_ciphertext AS prev
           FROM watch_keys w JOIN agents a ON a.id = w.agent_id WHERE w.agent_id = $1`,
        [agentId],
      )
    ).rows[0];
    if (!r) return [];
    const keys = [await secrets.open(r.org_id, r.cur, r.agent_key)];
    if (r.prev) keys.push(await secrets.open(r.org_id, r.prev, r.agent_key));
    return keys;
  };
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((r) => {
    const t = setTimeout(r, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        r();
      },
      { once: true },
    );
  });

const code = (e: unknown) => (e as AfrError).code ?? "ERROR";

export async function runWatcher(o: WatcherServiceOptions): Promise<void> {
  const { pool, chainId, signal, logger } = o;
  const followMs = o.followMs ?? 2_000;
  const sweepMs = o.sweepMs ?? 5_000;
  const reconcileMs = o.reconcileMs ?? 60_000;
  const now = o.now ?? Date.now;
  const lockKey = (WATCHER_LOCK_KEY + chainId).toString();

  const lock = await pool.connect();
  let lost = false;
  lock.on("error", () => {
    lost = true;
  });
  let held = false;
  const stops: (() => Promise<void>)[] = [];
  try {
    while (!signal.aborted && !held) {
      held = (await lock.query("SELECT pg_try_advisory_lock($1) AS ok", [lockKey])).rows[0].ok;
      if (!held) await sleep(o.retryLockMs ?? 10_000, signal);
    }
    if (!held) return;
    logger?.info({ event: "leader", chain_id: chainId.toString() }, "watcher leader lock held");

    const db = new PgWatcherDb(pool);
    const watched = new WatchedSet(db, chainId);
    await watched.reload();
    const follower = new HeadFollower({
      chainId,
      client: o.client,
      db,
      watched,
      ...(o.startBlock !== undefined ? { startBlock: o.startBlock } : {}),
    });
    const matcher = new Matcher({
      chainId,
      db,
      watchKeys: pgWatchKeys(pool, o.secrets),
      now,
      onEvent:
        o.onEvent ??
        ((e) =>
          logger?.info({
            event: e.type,
            agent: e.agentId,
            chain_id: chainId.toString(),
            ...("tx" in e ? { tx: e.tx } : { lane: e.lane, seq: e.seq.toString() }),
          })),
    });
    let reloadWatched = false;
    let sweepSoon = false;
    stops.push(
      await listen(pool, {
        watched_changed: (p) => {
          if (p === chainId.toString()) reloadWatched = true;
        },
        afr_intents: () => {
          sweepSoon = true;
        },
        // migration v7 trigger on watch_keys updates (rotation): drop the cached keys
        afr_watch_keys: (p) => p && matcher.forgetKeys(p),
      }),
    );

    let head: bigint | undefined;
    let lastSweep = 0;
    let lastReconcile = 0;
    const step = async (name: string, fn: () => Promise<unknown>) =>
      fn().catch((e) => logger?.error({ event: "watcher_step_failed", step: name, code: code(e) }));
    while (!signal.aborted && !lost) {
      if (reloadWatched) {
        reloadWatched = false;
        await step("watched", () => watched.reload());
      }
      await step("follow", async () => {
        head = (await follower.tick()).head;
      });
      if (now() - lastReconcile >= reconcileMs) {
        lastReconcile = now();
        await step("reconcile", async () => {
          if ((await reconcileAll(o, db)) > 0) sweepSoon = true;
        });
      }
      if (head !== undefined && (sweepSoon || now() - lastSweep >= sweepMs)) {
        sweepSoon = false;
        lastSweep = now();
        const h = head;
        await step("sweep", () => matcher.sweep(h));
      }
      await sleep(followMs, signal);
    }
    if (lost) throw new AfrError("LEADER_LOST", "leader connection dropped");
  } finally {
    for (const s of stops) await s().catch(() => {});
    if (held && !lost) await lock.query("SELECT pg_advisory_unlock($1)", [lockKey]).catch(() => {});
    lock.release(lost);
  }
}

/** Every active agent's lanes; the writer allowlist comes from the agent's registration (L5 §4). */
async function reconcileAll(o: WatcherServiceOptions, db: PgWatcherDb): Promise<number> {
  const { rows } = await o.pool.query<{ id: string; agent_id: string; lane: number }>(
    `SELECT a.id, a.agent_id, l.lane FROM agent_lanes l JOIN agents a ON a.id = l.agent_id
      WHERE a.status = 'active' ORDER BY a.id, l.lane`,
  );
  const writers = new Map<string, Hex[] | undefined>();
  let added = 0;
  for (const r of rows) {
    try {
      if (!writers.has(r.agent_id)) {
        const w = (await o.identity.resolve(r.agent_id)).afr?.afr.arkiv.writers;
        writers.set(r.agent_id, w?.length ? w.map((x) => x.toLowerCase() as Hex) : undefined);
      }
      const w = writers.get(r.agent_id);
      added += await reconcileLane({
        db,
        store: o.store,
        identity: o.identity,
        agentId: r.id,
        agent: r.agent_id,
        lane: r.lane,
        ...(w ? { writers: w } : {}),
      });
    } catch (e) {
      // one agent's registration or RPC trouble doesn't stop the others
      o.logger?.error({ event: "reconcile_failed", agent: r.id, lane: r.lane, code: code(e) });
    }
  }
  return added;
}
