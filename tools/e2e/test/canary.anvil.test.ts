// W9 (L6 §10, P4-07): a canary round against the real watcher service on anvil + Postgres: the logged
// self-transfer matches, the unlogged one raises exactly one UNLOGGED_TX, and the canary acks it. A second
// round provisions nothing new and passes again. Needs AFR_PG_URL and anvil; skipped without them.
import { randomBytes } from "node:crypto";
import { localKeyWrapper, migrate, OrgSecrets } from "@afr/api";
import { MemoryChain, MemoryStore } from "@afr/store";
import { staticIdentityReader } from "@afr/verifier";
import { canaryAgentId, canaryRound, PgAlerts, provisionCanary, runWatcher } from "@afr/watcher";
import pg from "pg";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { ANVIL, startAnvil } from "../../../apps/anchor/test/fixtures/world.js";

const URL = process.env.AFR_PG_URL;
const CHAIN = BigInt(foundry.id);
const CANARY = privateKeyToAccount(
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
); // anvil #3

describe.skipIf(!URL || !ANVIL)("canary (W9)", () => {
  const schema = `afr_canary_${randomBytes(4).toString("hex")}`;
  let pool: pg.Pool;
  let anvil: Awaited<ReturnType<typeof startAnvil>>;
  const kek = localKeyWrapper(new Uint8Array(randomBytes(32)));

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 8, options: `-c search_path=${schema}` });
    await migrate(pool);
    anvil = await startAnvil();
  }, 30_000);
  afterAll(async () => {
    anvil?.stop();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  test("exactly one UNLOGGED_TX per round, the logged tx matched, auto-acked", async () => {
    const o = {
      pool,
      secrets: new OrgSecrets(pool, kek),
      client: anvil.pc,
      account: CANARY,
      chainId: CHAIN,
      pollMs: 100,
      alertTimeoutMs: 15_000,
    };
    const agentId = await provisionCanary(o);
    expect(await provisionCanary(o)).toBe(agentId); // idempotent
    const stop = new AbortController();
    const watcher = runWatcher({
      pool,
      chainId: CHAIN,
      client: anvil.pc,
      store: new MemoryStore(new MemoryChain(), `0x${"a1".repeat(20)}`),
      identity: staticIdentityReader(`0x${"0a".repeat(20)}`),
      secrets: new OrgSecrets(pool, kek),
      signal: stop.signal,
      alerts: new PgAlerts(pool),
      followMs: 50,
      sweepMs: 50,
      retryLockMs: 50,
      now: () => Date.now() + 20_000, // past the canary agent's 15 s grace at once
    });
    try {
      for (let round = 1; round <= 2; round++) {
        const r = await canaryRound(o, agentId);
        expect(r).toMatchObject({ ok: true });
        const { rows } = await pool.query(
          "SELECT dedupe_key, status FROM alerts WHERE agent_id = $1 ORDER BY first_seen_at",
          [agentId],
        );
        expect(rows).toHaveLength(round);
        expect(rows.at(-1)).toEqual({
          dedupe_key: `UNLOGGED_TX:${CHAIN}:${r.unlogged}`,
          status: "acked",
        });
      }
      const events = await pool.query(
        `SELECT kind, actor FROM alert_events e JOIN alerts a ON a.id = e.alert_id
          WHERE a.agent_id = $1 ORDER BY e.id`,
        [agentId],
      );
      expect(events.rows.filter((e) => e.actor === "canary").map((e) => e.kind)).toEqual([
        "acked",
        "acked",
      ]);
      const n = await pool.query("SELECT count(*)::int AS n FROM agents WHERE agent_id = $1", [
        canaryAgentId(CHAIN),
      ]);
      expect(n.rows[0].n).toBe(1);
    } finally {
      stop.abort();
      await watcher;
    }
  }, 60_000);

  test("a low balance fails the round without sending", async () => {
    const r = await canaryRound(
      {
        pool,
        secrets: new OrgSecrets(pool, kek),
        client: anvil.pc,
        account: privateKeyToAccount(`0x${"0e".repeat(32)}`), // unfunded
        chainId: CHAIN,
      },
      "00000000-0000-4000-8000-000000000000",
    );
    expect(r).toEqual({ ok: false, code: "LOW_BALANCE" });
  });
});
