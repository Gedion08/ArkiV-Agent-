// P4-01/02 on Postgres (migration v5): the head follower on anvil over PgWatcherDb (cursor + ring survive a
// restart, a reorg orphans the observed tx), and watched_addresses changes arrive via LISTEN watched_changed.
// Needs AFR_PG_URL and anvil; skipped without them.
import { randomBytes } from "node:crypto";
import { migrate } from "@afr/api";
import { HeadFollower, listenWatched, PgWatcherDb, WatchedSet } from "@afr/watcher";
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

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 4, options: `-c search_path=${schema}` });
    await migrate(pool);
    const org = (await pool.query("INSERT INTO orgs (name) VALUES ('w') RETURNING id")).rows[0].id;
    agentId = (
      await pool.query(
        "INSERT INTO agents (org_id, agent_id, agent_key, name) VALUES ($1, 'local:w', $2, 'w') RETURNING id",
        [org, randomBytes(32)],
      )
    ).rows[0].id;
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
});
