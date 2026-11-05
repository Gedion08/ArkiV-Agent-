// P4-01…04 on Postgres (migrations v5–v7): the head follower on anvil over PgWatcherDb (cursor + ring survive
// a restart, a reorg orphans the observed tx), watched_addresses changes via LISTEN watched_changed, the
// matcher's SQL (tx_intents, batch_commitments, tx_matches) with the watch key opened from watch_keys, and the
// service loop (runWatcher): leader lock, per-agent grace, rotation picked up through LISTEN afr_watch_keys.
// Needs AFR_PG_URL and anvil; skipped without them.
import { randomBytes } from "node:crypto";
import { localKeyWrapper, migrate, OrgSecrets } from "@afr/api";
import { nonceCommit, txCommit } from "@afr/crypto";
import { MemoryChain, MemoryStore } from "@afr/store";
import { staticIdentityReader } from "@afr/verifier";
import {
  HeadFollower,
  listenIntents,
  listenWatched,
  type MatchEvent,
  Matcher,
  PgWatcherDb,
  pgWatchKeys,
  runWatcher,
  WATCHER_LOCK_KEY,
  WatchedSet,
} from "@afr/watcher";
import pg from "pg";
import { createTestClient, createWalletClient, type Hex, http, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { ANVIL, startAnvil } from "../../../apps/anchor/test/fixtures/world.js";

const URL = process.env.AFR_PG_URL;
const CHAIN = BigInt(foundry.id);
const WATCHED = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);

describe.skipIf(!URL || !ANVIL)("watcher on Postgres", () => {
  const schema = `afr_e2e_${randomBytes(4).toString("hex")}`;
  let pool: pg.Pool;
  let anvil: Awaited<ReturnType<typeof startAnvil>>;
  let agentId: string;
  let org: string;
  let ak: Buffer;
  const secrets = () => new OrgSecrets(pool, localKeyWrapper(KEK));
  const KEK = new Uint8Array(randomBytes(32));
  const wk = new Uint8Array(randomBytes(32));

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 8, options: `-c search_path=${schema}` });
    await migrate(pool);
    org = (await pool.query("INSERT INTO orgs (name) VALUES ('w') RETURNING id")).rows[0].id;
    ak = randomBytes(32);
    agentId = (
      await pool.query(
        "INSERT INTO agents (org_id, agent_id, agent_key, name) VALUES ($1, 'local:w', $2, 'w') RETURNING id",
        [org, ak],
      )
    ).rows[0].id;
    await pool.query("INSERT INTO watch_keys (agent_id, kms_ciphertext) VALUES ($1, $2)", [
      agentId,
      await secrets().seal(org, wk, ak),
    ]);
    await pool.query(
      "INSERT INTO watched_addresses (org_id, agent_id, chain_id, address, kind) VALUES ($1, $2, $3, $4, 'eoa')",
      [org, agentId, CHAIN.toString(), Buffer.from(WATCHED.address.slice(2).toLowerCase(), "hex")],
    );
    anvil = await startAnvil();
  }, 30_000);
  afterAll(async () => {
    anvil?.stop();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  test("observes, survives a restart, and orphans on a reorg", async () => {
    const db = new PgWatcherDb(pool);
    const watched = new WatchedSet(db, CHAIN);
    await watched.reload();
    const t = createTestClient({ chain: foundry, mode: "anvil", transport: http(anvil.url) });
    const w = createWalletClient({ account: WATCHED, chain: foundry, transport: http(anvil.url) });
    const send = async () => {
      const hash = await w.sendTransaction({
        to: `0x${"ee".repeat(20)}`,
        value: parseEther("0.001"),
      });
      await anvil.pc.waitForTransactionReceipt({ hash });
      return hash;
    };
    const follower = () =>
      new HeadFollower({ chainId: CHAIN, client: anvil.pc, db, watched, startBlock: 1n });
    const status = async (h: Hex) =>
      (
        await pool.query("SELECT status, agent_ids FROM observed_txs WHERE tx_hash = $1", [
          Buffer.from(h.slice(2), "hex"),
        ])
      ).rows[0];

    const snap = await t.snapshot();
    const a = await send();
    await follower().tick();
    expect(await status(a)).toEqual({ status: "seen", agent_ids: [agentId] });
    await t.mine({ blocks: 2 });
    await follower().tick(); // a new instance: the cursor and ring come from chain_cursors
    const cur = await db.cursor(CHAIN);
    expect(cur?.number).toBe(await anvil.pc.getBlockNumber({ cacheTime: 0 }));
    expect(cur?.ring.map(([n]) => n)).toEqual([0n, 1n, 2n]); // the blocks below the cursor (3)

    await t.revert({ id: snap });
    await t.mine({ blocks: 4 });
    const r = await follower().tick();
    expect(r.reorgs).toEqual([0n]);
    expect(await status(a)).toMatchObject({ status: "orphaned" });
  });

  test("watched_addresses changes reach a listener for that chain only", async () => {
    const got: string[] = [];
    const stop = await listenWatched(pool, CHAIN, () => got.push("hit"));
    try {
      const org = (await pool.query("SELECT org_id FROM agents WHERE id = $1", [agentId])).rows[0]
        .org_id;
      const add = (chain: bigint) =>
        pool.query(
          "INSERT INTO watched_addresses (org_id, agent_id, chain_id, address, kind) VALUES ($1, $2, $3, $4, 'eoa')",
          [org, agentId, chain.toString(), randomBytes(20)],
        );
      await add(8453n); // another chain: ignored
      await add(CHAIN);
      for (let i = 0; i < 50 && !got.length; i++) await new Promise((r) => setTimeout(r, 20));
      expect(got).toEqual(["hit"]);
    } finally {
      await stop();
    }
  });

  test("matcher on Postgres: exact, unlogged → late (Arkiv batch), not mined; the watch key from watch_keys", async () => {
    const db = new PgWatcherDb(pool);
    const CH = 990001n; // a chain of its own: rows are written directly, no follower
    const from = WATCHED.address.toLowerCase() as Hex;
    const tx = (n: number) => ({
      chainId: CH,
      hash: `0x${n.toString(16).padStart(64, "0")}` as Hex,
      blockNumber: 10n,
      blockHash: `0x${"bb".repeat(32)}` as Hex,
      from,
      nonce: BigInt(n),
      to: null,
      agentIds: [agentId],
    });
    const [a, b] = [tx(1), tx(2)];
    await db.commitBlock(CH, { number: 10n, hash: a.blockHash, ring: [] }, [a, b]);
    const intent = (seq: number, txc: Hex | null, nc: Hex, ageS = 0) =>
      pool.query(
        `INSERT INTO tx_intents (agent_id, lane, seq, chain_id, tx_commit, nonce_commit, received_at)
         VALUES ($1, 0, $2, $3, $4, $5, now() - make_interval(secs => $6))`,
        [
          agentId,
          seq,
          CH.toString(),
          txc && Buffer.from(txc.slice(2), "hex"),
          Buffer.from(nc.slice(2), "hex"),
          ageS,
        ],
      );
    const notified: string[] = [];
    const stop = await listenIntents(pool, (id) => notified.push(id));
    await intent(1, txCommit(wk, CH, a.hash), nonceCommit(wk, CH, from, a.nonce));
    await pool.query("SELECT pg_notify('afr_intents', $1)", [agentId]); // as the intents route does
    await intent(2, null, nonceCommit(wk, CH, from, 77n), 7200); // never mined, 2 h old

    let now = Date.now();
    // what the service wires: the sealed key opened with the agent key as AAD
    const m = new Matcher({
      chainId: CH,
      db,
      watchKeys: pgWatchKeys(pool, secrets()),
      now: () => now,
    });
    expect(await m.sweep(10n)).toEqual([
      { type: "INTENT_NOT_MINED", agentId, chainId: CH, lane: 0, seq: 2n },
    ]);
    now += 61_000;
    expect(await m.sweep(10n)).toEqual([
      { type: "UNLOGGED_TX", agentId, chainId: CH, tx: b.hash, block: 10n },
    ]);
    // b's nonce commitment arrives in a reconciled batch: the alert resolves as a late intent
    await db.addBatchCommitments(agentId, 0, 4n, [], [nonceCommit(wk, CH, from, b.nonce)]);
    expect(await db.reconcileCursor(agentId, 0)).toBe(5n);
    expect(await m.sweep(10n)).toEqual([
      { type: "LATE_INTENT", agentId, chainId: CH, tx: b.hash, block: 10n },
    ]);
    expect(await m.sweep(10n)).toEqual([]);
    const kinds = (
      await pool.query("SELECT kind FROM tx_matches WHERE chain_id = $1 ORDER BY tx_hash", [
        CH.toString(),
      ])
    ).rows.map((r) => r.kind);
    expect(kinds).toEqual(["exact", "late_intent"]);
    for (let i = 0; i < 50 && !notified.length; i++) await new Promise((r) => setTimeout(r, 20));
    expect(notified).toEqual([agentId]);
    await stop();

    const sk = randomBytes(20);
    await pool.query(
      `INSERT INTO session_keys (agent_id, lane, address, not_before, not_after, delegation_entity)
       VALUES ($1, 0, $2, now(), now() + interval '1 day', $3)`,
      [agentId, sk, randomBytes(32)],
    );
    const addr = `0x${sk.toString("hex")}` as Hex;
    expect(await db.isSessionKey(agentId, 0, addr)).toBe(true);
    expect(await db.isSessionKey(agentId, 1, addr)).toBe(false);
    await pool.query("UPDATE session_keys SET revoked_at = now() WHERE address = $1", [sk]);
    expect(await db.isSessionKey(agentId, 0, addr)).toBe(false);
  });

  test("the service: one leader per chain, per-agent grace, a rotation reloads the key", async () => {
    const w = createWalletClient({ account: WATCHED, chain: foundry, transport: http(anvil.url) });
    const send = async () => {
      const hash = await w.sendTransaction({
        to: `0x${"ee".repeat(20)}`,
        value: parseEther("0.001"),
      });
      await anvil.pc.waitForTransactionReceipt({ hash });
      return hash;
    };
    const events: MatchEvent[] = [];
    const clock = { offset: 0 };
    const start = (signal: AbortSignal) =>
      runWatcher({
        pool,
        chainId: CHAIN,
        client: anvil.pc,
        store: new MemoryStore(new MemoryChain(), `0x${"a1".repeat(20)}`),
        identity: staticIdentityReader(`0x${"0a".repeat(20)}`),
        secrets: secrets(),
        signal,
        followMs: 50,
        sweepMs: 50,
        retryLockMs: 50,
        now: () => Date.now() + clock.offset,
        onEvent: (e) => void events.push(e),
      });
    const until = async (ok: () => boolean | Promise<boolean>) => {
      for (let i = 0; i < 200 && !(await ok()); i++) await new Promise((r) => setTimeout(r, 25));
      expect(await ok()).toBe(true);
    };
    const leaders = async () => {
      const key = WATCHER_LOCK_KEY + CHAIN;
      const { rows } = await pool.query(
        `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND granted
           AND classid = $1 AND objid = $2`,
        [(key >> 32n).toString(), (key & 0xffffffffn).toString()],
      );
      return rows[0].n as number;
    };
    const match = async (h: Hex) =>
      (
        await pool.query("SELECT kind FROM tx_matches WHERE tx_hash = $1", [
          Buffer.from(h.slice(2), "hex"),
        ])
      ).rows[0]?.kind;

    const a = new AbortController();
    const b = new AbortController();
    const runA = start(a.signal);
    await until(async () => (await leaders()) === 1);
    const runB = start(b.signal); // waits for the lock
    await new Promise((r) => setTimeout(r, 200));
    expect(await leaders()).toBe(1);
    b.abort();
    await runB;

    try {
      await pool.query("UPDATE agents SET watch_grace_s = 15 WHERE id = $1", [agentId]);
      const raw = await send();
      await until(async () => (await match(raw)) === undefined && events.length === 0);
      clock.offset = 16_000; // past this agent's 15 s grace (the default would be 60 s)
      await until(() => events.some((e) => e.type === "UNLOGGED_TX" && "tx" in e && e.tx === raw));

      // rotate (as POST /watch-key/rotate does): the trigger tells the service to drop its cached key
      const next = new Uint8Array(randomBytes(32));
      const s = secrets();
      await pool.query(
        `UPDATE watch_keys SET prev_kms_ciphertext = kms_ciphertext, kms_ciphertext = $2, rotated_at = now()
         WHERE agent_id = $1`,
        [agentId, await s.seal(org, next, ak)],
      );
      clock.offset = 0;
      const intentFor = async (key: Uint8Array, h: Hex, seq: number) => {
        const nonce = BigInt((await anvil.pc.getTransaction({ hash: h })).nonce);
        await pool.query(
          `INSERT INTO tx_intents (agent_id, lane, seq, chain_id, tx_commit, nonce_commit) VALUES ($1, 0, $2, $3, $4, $5)`,
          [
            agentId,
            seq,
            CHAIN.toString(),
            Buffer.from(txCommit(key, CHAIN, h).slice(2), "hex"),
            Buffer.from(nonceCommit(key, CHAIN, WATCHED.address, nonce).slice(2), "hex"),
          ],
        );
        await pool.query("SELECT pg_notify('afr_intents', $1)", [agentId]);
      };
      const old = await send(); // the recorder still on the old key
      await intentFor(wk, old, 100);
      const fresh = await send(); // the recorder on the new key
      await intentFor(next, fresh, 101);
      await until(async () => (await match(old)) === "exact" && (await match(fresh)) === "exact");
    } finally {
      a.abort();
      await runA;
    }
    expect(await leaders()).toBe(0);
  }, 30_000);
});
