// P2-13 apps/api v0 (L8 §10): SIWE + tenancy, P2 recorder HMAC, P5 idempotent checkpoints, plaintext
// guard. Needs AFR_PG_URL (pnpm local:up); each run gets its own schema. Skipped without it.
import { randomBytes } from "node:crypto";
import pg from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { buildServer, localKeyWrapper, migrate, signRecorderRequest } from "../src/index.js";

const URL = process.env.AFR_PG_URL;
const DOMAIN = "app.afr.test";
const AGENT_PREFIX = "eip155:84532:0x00000000000000000000000000000000000a8004:";
const h32 = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;
const nowS = () => Math.floor(Date.now() / 1000);

describe.skipIf(!URL)("apps/api v0", () => {
  const schema = `afr_api_test_${randomBytes(4).toString("hex")}`;
  let pool: pg.Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;
  const masterKey = randomBytes(32);

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 4, options: `-c search_path=${schema}` });
    await migrate(pool);
    await migrate(pool); // idempotent
    app = await buildServer({ pool, siweDomain: DOMAIN, keys: localKeyWrapper(masterKey) });
  });
  afterAll(async () => {
    await app?.close();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  /** SIWE login; returns cookie (+ CSRF) headers for later calls. */
  async function login() {
    const acct = privateKeyToAccount(generatePrivateKey());
    const { nonce } = (await app.inject({ method: "GET", url: "/v1/auth/nonce" })).json();
    const message = createSiweMessage({
      address: acct.address,
      chainId: 8453,
      domain: DOMAIN,
      nonce,
      uri: `https://${DOMAIN}`,
      version: "1",
    });
    const signature = await acct.signMessage({ message });
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message, signature },
    });
    expect(res.statusCode).toBe(200);
    const session = res.cookies.find((c) => c.name === "__Host-afr");
    expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/" });
    const cookie = res.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    return {
      acct,
      message,
      signature,
      get: { cookie },
      headers: { cookie, "x-csrf-token": res.json().csrf as string },
    };
  }

  async function setup() {
    const u = await login();
    const org = (
      await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: u.headers,
        payload: { name: "Acme" },
      })
    ).json();
    const created = await app.inject({
      method: "POST",
      url: `/v1/orgs/${org.id}/agents`,
      headers: u.headers,
      payload: {
        agent_id: `${AGENT_PREFIX}${randomBytes(3).readUIntBE(0, 3)}`,
        name: "treasury",
        approval_threshold_cents: "10000",
      },
    });
    expect(created.statusCode).toBe(201);
    const { agent, watch_key } = created.json();
    const key = (
      await app.inject({
        method: "POST",
        url: `/v1/agents/${agent.id}/recorder-keys`,
        headers: u.headers,
        payload: { lanes: [0] },
      })
    ).json();
    return { u, org, agent, watchKey: watch_key as string, key };
  }

  /** A signed recorder request (L8 §2). */
  const rec = (token: string, method: "GET" | "POST", url: string, body?: unknown, skewS = 0) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const headers = signRecorderRequest(token, method, url, payload, nowS() + skewS);
    return app.inject({
      method,
      url,
      headers: { ...headers, ...(payload ? { "content-type": "application/json" } : {}) },
      ...(payload ? { payload } : {}),
    });
  };

  test("SIWE: session cookie, single-use nonce, CSRF on mutations, me", async () => {
    const u = await login();
    const replay = await app.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message: u.message, signature: u.signature },
    });
    expect(replay.statusCode).toBe(401); // nonce already consumed
    const me = (await app.inject({ method: "GET", url: "/v1/me", headers: u.get })).json();
    expect(me.user.wallet).toBe(u.acct.address.toLowerCase());
    const noCsrf = await app.inject({
      method: "POST",
      url: "/v1/orgs",
      headers: u.get,
      payload: { name: "x" },
    });
    expect(noCsrf.statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/v1/me" })).statusCode).toBe(401);
  });

  test("agents: watch key returned once and stored only wrapped; tenancy 404 across orgs", async () => {
    const { org, agent, watchKey, key } = await setup();
    expect(agent).toMatchObject({
      privacy_level: 0,
      retention_days: 365,
      approval_threshold_cents: "10000",
    });
    expect(watchKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(key.key).toMatch(/^afr_rk_[0-9a-f]{16}_[0-9a-f]{64}$/);
    const { rows } = await pool.query("SELECT kms_ciphertext FROM watch_keys WHERE agent_id = $1", [
      agent.id,
    ]);
    const stored: Buffer = rows[0].kms_ciphertext;
    expect(stored.includes(Buffer.from(watchKey.slice(2), "hex"))).toBe(false);
    const aad = Buffer.from(agent.agent_key.slice(2), "hex");
    const unwrapped = localKeyWrapper(masterKey).unwrap(stored, aad);
    expect(`0x${Buffer.from(unwrapped).toString("hex")}`).toBe(watchKey);
    const secret = key.key.split("_").at(-1) as string;
    const keyRow = (
      await pool.query("SELECT secret_hash FROM recorder_keys WHERE id = $1", [key.id])
    ).rows[0];
    expect(keyRow.secret_hash.includes(Buffer.from(secret))).toBe(false);

    const other = await login();
    for (const url of [`/v1/orgs/${org.id}`, `/v1/orgs/${org.id}/agents`, `/v1/agents/${agent.id}`])
      expect((await app.inject({ method: "GET", url, headers: other.get })).statusCode).toBe(404);
    const steal = await app.inject({
      method: "POST",
      url: `/v1/agents/${agent.id}/recorder-keys`,
      headers: other.headers,
      payload: {},
    });
    expect(steal.statusCode).toBe(404);
  });

  test("P2: recorder HMAC — valid accepted; stale, tampered, wrong-secret, revoked, wrong-lane rejected", async () => {
    const { u, agent, key } = await setup();
    const hb = {
      agent_key: agent.agent_key,
      lane: 0,
      next_seq: "12",
      pending_batches: 0,
      store_lag_s: 1,
      key_not_after: "1900000000",
      version: "0.1.0",
    };
    const url = "/v1/recorder/heartbeat";
    expect((await rec(key.key, "POST", url, hb)).statusCode).toBe(200);
    expect((await rec(key.key, "POST", url, hb, -360)).statusCode).toBe(401); // > 5 min old
    const headers = signRecorderRequest(key.key, "POST", url, JSON.stringify(hb), nowS());
    const tampered = await app.inject({
      method: "POST",
      url,
      headers: { ...headers, "content-type": "application/json" },
      payload: JSON.stringify({ ...hb, next_seq: "13" }),
    });
    expect(tampered.statusCode).toBe(401);
    const wrongSecret = key.key.replace(/.$/, (c: string) => (c === "0" ? "1" : "0"));
    expect((await rec(wrongSecret, "POST", url, hb)).statusCode).toBe(401);
    expect((await rec(key.key, "POST", url, { ...hb, lane: 3 })).statusCode).toBe(403);
    const lane = (
      await pool.query("SELECT recorder_version, heartbeat FROM agent_lanes WHERE agent_id = $1", [
        agent.id,
      ])
    ).rows[0];
    expect(lane).toMatchObject({ recorder_version: "0.1.0", heartbeat: { next_seq: "12" } });

    const revoke = await app.inject({
      method: "DELETE",
      url: `/v1/agents/${agent.id}/recorder-keys/${key.id}`,
      headers: u.headers,
    });
    expect(revoke.statusCode).toBe(200);
    expect((await rec(key.key, "POST", url, hb)).statusCode).toBe(401);
  });

  test("P5: a duplicate checkpoint → one row; lanes advance; intents and delegations idempotent", async () => {
    const { agent, key } = await setup();
    const cp = {
      lane: 0,
      seq_from: "0",
      seq_to: "9",
      batch_root: h32(1),
      chain_root: h32(2),
      entity_key: h32(3),
      arkiv_tx: h32(4),
    };
    const first = await rec(key.key, "POST", "/v1/recorder/checkpoints", cp);
    const again = await rec(key.key, "POST", "/v1/recorder/checkpoints", cp);
    expect([first.statusCode, again.statusCode]).toEqual([201, 200]);
    expect(again.json()).toMatchObject({ duplicate: true });
    const count = async (t: string) =>
      Number(
        (await pool.query(`SELECT count(*) FROM ${t} WHERE agent_id = $1`, [agent.id])).rows[0]
          .count,
      );
    expect(await count("checkpoints")).toBe(1);
    expect(await count("batches_index")).toBe(1);
    const lane = (
      await pool.query("SELECT last_seq FROM agent_lanes WHERE agent_id = $1", [agent.id])
    ).rows[0];
    expect(lane.last_seq).toBe("9");

    const intents = { items: [{ lane: 0, seq: "3", chain_id: "8453", nonce_commit: h32(5) }] };
    const i1 = await rec(key.key, "POST", "/v1/recorder/intents", intents);
    const i2 = await rec(key.key, "POST", "/v1/recorder/intents", intents);
    expect([i1.json(), i2.json()]).toEqual([{ accepted: 1 }, { accepted: 0 }]);
    const d = {
      lane: 0,
      session_key: `0x${"Ab".repeat(20)}`,
      not_before: "1800000000",
      not_after: "1800086400",
      entity_key: h32(6),
    };
    expect((await rec(key.key, "POST", "/v1/recorder/delegations", d)).statusCode).toBe(201);
    expect((await rec(key.key, "POST", "/v1/recorder/delegations", d)).statusCode).toBe(200);
    expect(await count("session_keys")).toBe(1);
  });

  test("config: ETag round trip; plaintext guard rejects unknown fields without echoing them", async () => {
    const { key } = await setup();
    const cfg = await rec(key.key, "GET", "/v1/recorder/config");
    expect(cfg.json()).toEqual({
      readers: [],
      policy: null,
      approval_threshold_cents: "10000",
      privacy_level: 0,
    });
    const signed = signRecorderRequest(key.key, "GET", "/v1/recorder/config", "", nowS());
    const cached = await app.inject({
      method: "GET",
      url: "/v1/recorder/config",
      headers: { ...signed, "if-none-match": cfg.headers.etag as string },
    });
    expect(cached.statusCode).toBe(304);

    const secretText = "plaintext-canary-7f3a";
    const bad = await rec(key.key, "POST", "/v1/recorder/checkpoints", {
      lane: 0,
      seq_from: "0",
      seq_to: "1",
      batch_root: h32(1),
      chain_root: h32(2),
      entity_key: h32(3),
      body: secretText,
    });
    expect(bad.statusCode).toBe(400);
    expect(bad.body.includes(secretText)).toBe(false);
  });
});
