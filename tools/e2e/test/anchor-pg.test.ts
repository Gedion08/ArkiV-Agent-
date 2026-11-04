// P3-05/06 across apps: recorder notices → API (Postgres queue) → anchor service on anvil (PgAnchorDb) →
// GET /v1/recorder/config reports the anchored checkpoint. Needs AFR_PG_URL and anvil; skipped without them.
import { randomBytes } from "node:crypto";
import { AnchorService, PgAnchorDb, PgWriteJournal, runAsLeader } from "@afr/anchor";
import {
  buildServer,
  localKeyWrapper,
  migrate,
  newRecorderKey,
  signRecorderRequest,
} from "@afr/api";
import pg from "pg";
import type { Hex } from "viem";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  ANVIL,
  anchorChain,
  deployAnchor,
  startAnvil,
  World,
} from "../../../apps/anchor/test/fixtures/world.js";

const URL = process.env.AFR_PG_URL;
const nowS = () => Math.floor(Date.now() / 1000);
const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");

describe.skipIf(!URL || !ANVIL)("anchor service on Postgres", () => {
  const schema = `afr_e2e_${randomBytes(4).toString("hex")}`;
  let pool: pg.Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let anvil: Awaited<ReturnType<typeof startAnvil>>;

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 4, options: `-c search_path=${schema}` });
    await migrate(pool);
    app = await buildServer({
      pool,
      siweDomain: "app.afr.test",
      keys: localKeyWrapper(randomBytes(32)),
    });
    anvil = await startAnvil();
  }, 30_000);
  afterAll(async () => {
    anvil?.stop();
    await app?.close();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  const rec = (token: string, method: "GET" | "POST", url: string, body?: unknown) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    return app.inject({
      method,
      url,
      headers: {
        ...signRecorderRequest(token, method, url, payload, nowS()),
        ...(payload ? { "content-type": "application/json" } : {}),
      },
      ...(payload ? { payload } : {}),
    });
  };

  test("notices → validated → anchored on-chain → config `anchored`; the older checkpoint superseded", async () => {
    const w = new World();
    const b9 = await w.batch({ agent: 1, lane: 0, seqTo: 9n });
    const b19 = await w.batch({ agent: 1, lane: 0, seqTo: 19n });

    // an org, its agent and a recorder key, as the dashboard would create them
    const org = (await pool.query("INSERT INTO orgs (name) VALUES ('e2e') RETURNING id")).rows[0]
      .id;
    const agent = (
      await pool.query(
        "INSERT INTO agents (org_id, agent_id, agent_key, name) VALUES ($1, $2, $3, 'e2e') RETURNING id",
        [org, b9.agentId, buf(b9.agentKey)],
      )
    ).rows[0].id;
    const key = newRecorderKey();
    await pool.query(
      "INSERT INTO recorder_keys (id, org_id, agent_id, secret_hash, lanes) VALUES ($1, $2, $3, $4, '{0}')",
      [key.id, org, agent, key.secretHash],
    );

    const d = await rec(key.token, "POST", "/v1/recorder/delegations", {
      lane: 0,
      session_key: b9.sessionKey,
      not_before: String(nowS() - 60),
      not_after: String(nowS() + 3600),
      entity_key: `0x${"0d".repeat(32)}`,
    });
    expect(d.statusCode).toBe(201);
    for (const [b, seqTo] of [
      [b9, "9"],
      [b19, "19"],
    ] as const) {
      const r = await rec(key.token, "POST", "/v1/recorder/checkpoints", {
        lane: 0,
        seq_from: b.seqFrom.toString(),
        seq_to: seqTo,
        batch_root: b.batchRoot,
        chain_root: b.chainRoot,
        entity_key: b.entity,
      });
      expect(r.statusCode).toBe(201);
    }

    const contract = await deployAnchor(anvil.url, anvil.pc);
    const db = new PgAnchorDb(pool);
    const svc = new AnchorService({
      db,
      store: w.store,
      chain: anchorChain(anvil.pc, contract),
      cadenceMs: 0,
    });
    await svc.tick();

    const [a] = await db.anchorsIn(["published", "safe", "finalized"]);
    expect(a?.leaves).toHaveLength(1);
    const { rows } = await pool.query(
      "SELECT seq_to::text, status, anchor_epoch::text AS epoch, cardinality(proof) AS proof FROM checkpoints ORDER BY checkpoints.seq_to",
    );
    expect(rows).toEqual([
      { seq_to: "9", status: "superseded", epoch: "1", proof: null },
      { seq_to: "19", status: "anchored", epoch: "1", proof: 0 }, // single-leaf tree: empty proof
    ]);

    const cfg = await rec(key.token, "GET", "/v1/recorder/config");
    expect(cfg.json().anchored).toEqual([
      { lane: 0, seq_to: "19", epoch: "1", anchor_tx: a?.txHash, chain_root: b19.chainRoot },
    ]);

    // a second tick finds nothing new to anchor
    await svc.tick();
    expect((await pool.query("SELECT count(*)::int AS n FROM anchors")).rows[0].n).toBe(1);
  }, 60_000);

  test("PgWriteJournal: upsert + read back", async () => {
    const j = new PgWriteJournal(pool);
    const id = `0x${"ab".repeat(32)}` as Hex;
    expect(await j.get(id)).toBeUndefined();
    await j.set({ id, state: "intent" });
    await j.set({ id, state: "submitting", txHash: `0x${"01".repeat(32)}`, nonce: 3 });
    expect(await j.get(id)).toEqual({
      id,
      state: "submitting",
      txHash: `0x${"01".repeat(32)}`,
      nonce: 3,
    });
  });

  test("leader lock: one leader ticks; a standby takes over when it stops", async () => {
    const ticks = { a: 0, b: 0 };
    const stopA = new AbortController();
    const stopB = new AbortController();
    const opts = { pool, intervalMs: 10, retryLockMs: 20 };
    const a = runAsLeader({ ...opts, signal: stopA.signal, tick: async () => void ticks.a++ });
    await new Promise((r) => setTimeout(r, 100));
    const b = runAsLeader({ ...opts, signal: stopB.signal, tick: async () => void ticks.b++ });
    await new Promise((r) => setTimeout(r, 150));
    expect(ticks.a).toBeGreaterThan(0);
    expect(ticks.b).toBe(0); // standby: lock held by a
    stopA.abort();
    await a;
    await new Promise((r) => setTimeout(r, 150));
    expect(ticks.b).toBeGreaterThan(0);
    stopB.abort();
    await b;
  });
});
