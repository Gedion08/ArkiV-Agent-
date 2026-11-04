// apps/api (L8 §10): SIWE + tenancy (+ RLS), members/invitations, agent settings, watched addresses, read
// views, P2 recorder HMAC, P5 idempotent checkpoints, plaintext guard, rate limits, security headers.
// Needs AFR_PG_URL (pnpm local:up); each run gets its own schema. Skipped without it.
import { randomBytes } from "node:crypto";
import pg from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  buildServer,
  inOrg,
  localKeyWrapper,
  migrate,
  OrgSecrets,
  signRecorderRequest,
} from "../src/index.js";

const URL = process.env.AFR_PG_URL;
const DOMAIN = "app.afr.test";
const AGENT_PREFIX = "eip155:84532:0x00000000000000000000000000000000000a8004:";
const h32 = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;
const nowS = () => Math.floor(Date.now() / 1000);
/** A fresh client IP per login, so the per-IP SIWE limit (§7) doesn't trip across tests. */
const ip = () => `10.${randomBytes(3).join(".")}`;

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
  async function login(acct = privateKeyToAccount(generatePrivateKey())) {
    const remoteAddress = ip();
    const { nonce } = (
      await app.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress })
    ).json();
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
      remoteAddress,
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
    // sealed under the org's DEK, which is itself stored only wrapped by the KEK
    const aad = Buffer.from(agent.agent_key.slice(2), "hex");
    const secrets = new OrgSecrets(pool, localKeyWrapper(masterKey));
    const unwrapped = await secrets.open(org.id, stored, aad);
    expect(`0x${Buffer.from(unwrapped).toString("hex")}`).toBe(watchKey);
    await expect(secrets.open(org.id, stored, Buffer.alloc(32))).rejects.toThrow(); // AAD binds the agent
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
      anchored: [],
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
  test("members: add by wallet, owner-only owner grants, last owner kept, viewer can't write", async () => {
    const { u, org } = await setup();
    const other = await login();
    const wallet = other.acct.address.toLowerCase();
    const add = (by: typeof u, w: string, role: string) =>
      app.inject({
        method: "POST",
        url: `/v1/orgs/${org.id}/members`,
        headers: by.headers,
        payload: { wallet: w, role },
      });
    expect((await add(u, wallet, "admin")).json()).toMatchObject({ wallet, role: "admin" });
    // an admin can't mint owners, nor demote one
    expect(
      (await add(other, privateKeyToAccount(generatePrivateKey()).address, "owner")).statusCode,
    ).toBe(403);
    expect((await add(other, u.acct.address, "viewer")).statusCode).toBe(403);
    // the only owner can't demote themself
    expect((await add(u, u.acct.address, "admin")).statusCode).toBe(409);
    const members = await app.inject({
      method: "GET",
      url: `/v1/orgs/${org.id}/members`,
      headers: other.get,
    });
    expect(
      members
        .json()
        .members.map((m: { role: string }) => m.role)
        .sort(),
    ).toEqual(["admin", "owner"]);
    // viewer: reads yes, writes no
    expect((await add(u, wallet, "viewer")).statusCode).toBe(200);
    const write = await app.inject({
      method: "PATCH",
      url: `/v1/orgs/${org.id}`,
      headers: other.headers,
      payload: { name: "x" },
    });
    expect(write.statusCode).toBe(403);
    const leave = await app.inject({
      method: "DELETE",
      url: `/v1/orgs/${org.id}/members/${other.acct ? members.json().members.find((m: { wallet: string }) => m.wallet === wallet).user_id : ""}`,
      headers: other.headers,
    });
    expect(leave.statusCode).toBe(200); // anyone may leave
    expect(
      (await app.inject({ method: "GET", url: `/v1/orgs/${org.id}`, headers: other.get }))
        .statusCode,
    ).toBe(404);
  });

  test("invitations: wallet-bound, single use, expire; only owners invite owners", async () => {
    const { u, org } = await setup();
    const invitee = await login();
    const stranger = await login();
    const invite = (payload: object) =>
      app.inject({
        method: "POST",
        url: `/v1/orgs/${org.id}/invitations`,
        headers: u.headers,
        payload,
      });
    const res = await invite({ role: "engineer", wallet: invitee.acct.address });
    expect(res.statusCode).toBe(201);
    const { token } = res.json();
    expect(token).toMatch(/^afr_inv_[0-9a-f]{64}$/);
    const stored = await pool.query("SELECT token_hash FROM invitations WHERE org_id = $1", [
      org.id,
    ]);
    expect(stored.rows[0].token_hash.includes(Buffer.from(token))).toBe(false);
    const accept = (by: typeof u, t: string) =>
      app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: by.headers,
        payload: { token: t },
      });
    expect((await accept(stranger, token)).statusCode).toBe(404); // bound to another wallet
    expect((await accept(invitee, token)).json()).toEqual({ org_id: org.id, role: "engineer" });
    expect((await accept(invitee, token)).statusCode).toBe(404); // used up
    const open = (await invite({ role: "viewer" })).json().token;
    await pool.query(
      "UPDATE invitations SET expires_at = now() - interval '1 s' WHERE org_id = $1",
      [org.id],
    );
    expect((await accept(stranger, open)).statusCode).toBe(404); // expired
    const engineerInvites = await app.inject({
      method: "POST",
      url: `/v1/orgs/${org.id}/invitations`,
      headers: invitee.headers,
      payload: { role: "viewer" },
    });
    expect(engineerInvites.statusCode).toBe(403);
  });

  test("agents: PATCH settings, privacy needs a profile statement; watched addresses idempotent; cross-org 404", async () => {
    const { u, agent } = await setup();
    const patch = (payload: object, by = u) =>
      app.inject({ method: "PATCH", url: `/v1/agents/${agent.id}`, headers: by.headers, payload });
    const ok = await patch({
      name: "treasury-2",
      status: "paused",
      approval_threshold_cents: null,
    });
    expect(ok.json().agent).toMatchObject({
      name: "treasury-2",
      status: "paused",
      approval_threshold_cents: null,
    });
    expect((await patch({ privacy_level: 2 })).statusCode).toBe(400);
    expect((await patch({})).statusCode).toBe(400);

    const url = `/v1/agents/${agent.id}/watched-addresses`;
    const address = `0x${"Cd".repeat(20)}`;
    const add = () =>
      app.inject({
        method: "POST",
        url,
        headers: u.headers,
        payload: { chain_id: "8453", address, kind: "safe", since_block: "123" },
      });
    const first = await add();
    const again = await add();
    expect([first.statusCode, again.statusCode]).toEqual([201, 200]);
    expect(again.json()).toEqual(first.json());
    expect(first.json()).toMatchObject({
      address: address.toLowerCase(),
      kind: "safe",
      since_block: "123",
    });
    const list = await app.inject({ method: "GET", url, headers: u.get });
    expect(list.json().addresses).toHaveLength(1);

    const other = await login();
    expect((await patch({ name: "x" }, other)).statusCode).toBe(404);
    expect((await app.inject({ method: "GET", url, headers: other.get })).statusCode).toBe(404);
    const del = (by: typeof u) =>
      app.inject({ method: "DELETE", url: `${url}/${first.json().id}`, headers: by.headers });
    expect((await del(other)).statusCode).toBe(404);
    expect((await del(u)).statusCode).toBe(200);
    expect((await del(u)).statusCode).toBe(404);
  });

  test("read views: lanes, batch index and checkpoints with cursors", async () => {
    const { u, agent, key } = await setup();
    for (const [from, to] of [
      ["0", "4"],
      ["5", "9"],
      ["10", "14"],
    ])
      await rec(key.key, "POST", "/v1/recorder/checkpoints", {
        lane: 0,
        seq_from: from,
        seq_to: to,
        batch_root: h32(Number(to)),
        chain_root: h32(100 + Number(to)),
        entity_key: h32(200 + Number(to)),
      });
    await rec(key.key, "POST", "/v1/recorder/heartbeat", {
      lane: 0,
      next_seq: "15",
      pending_batches: 1,
      store_lag_s: 3,
      key_not_after: "1900000000",
      version: "0.1.0",
    });
    const get = (path: string) =>
      app.inject({ method: "GET", url: `/v1/agents/${agent.id}${path}`, headers: u.get });
    const lanes = (await get("/lanes")).json().lanes;
    expect(lanes).toEqual([
      expect.objectContaining({
        lane: 0,
        last_seq: "14",
        last_chain_root: h32(114),
        pending_batches: 1,
        store_lag_s: 3,
      }),
    ]);
    const page1 = (await get("/batches?lane=0&limit=2")).json();
    expect(page1.batches.map((b: { seq_from: string }) => b.seq_from)).toEqual(["0", "5"]);
    expect(page1.next_from_seq).toBe("10");
    const page2 = (await get(`/batches?lane=0&limit=2&from_seq=${page1.next_from_seq}`)).json();
    expect(page2).toMatchObject({
      batches: [expect.objectContaining({ seq_to: "14", arkiv_tx: null })],
      next_from_seq: null,
    });
    const cps = (await get("/checkpoints?limit=2")).json();
    expect(cps.checkpoints.map((c: { seq_to: string }) => c.seq_to)).toEqual(["4", "9"]);
    const rest = (await get(`/checkpoints?after_seq=${cps.next_after_seq}`)).json();
    expect(rest.checkpoints).toEqual([
      expect.objectContaining({ seq_to: "14", status: "pending", batch_entity: h32(214) }),
    ]);
    expect((await get("/batches?limit=501")).statusCode).toBe(400);
  });

  test("RLS: inside inOrg, other orgs' rows are invisible and can't be written, even without a WHERE", async () => {
    const a = await setup();
    const b = await setup();
    const seen = await inOrg(pool, a.org.id, async (q) => ({
      agents: (await q.query("SELECT id FROM agents")).rows.map((r) => r.id),
      keys: (await q.query("SELECT agent_id FROM recorder_keys")).rows.map((r) => r.agent_id),
      watch: (await q.query("SELECT agent_id FROM watch_keys")).rows.map((r) => r.agent_id),
      orgs: (await q.query("SELECT id FROM orgs")).rows.map((r) => r.id),
    }));
    expect(seen).toEqual({
      agents: [a.agent.id],
      keys: [a.agent.id],
      watch: [a.agent.id],
      orgs: [a.org.id],
    });
    await expect(
      inOrg(pool, a.org.id, (q) =>
        q.query(
          "INSERT INTO tx_intents (agent_id, lane, seq, chain_id, nonce_commit) VALUES ($1, 0, 1, 1, $2)",
          [b.agent.id, Buffer.alloc(32)],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
    const updated = await inOrg(pool, a.org.id, (q) =>
      q.query("UPDATE agents SET name = 'pwned' WHERE id = $1", [b.agent.id]),
    );
    expect(updated.rowCount).toBe(0);
  });

  test("§7/§8: nonce rate limit per IP, recorder limit per key, security headers", async () => {
    const remoteAddress = ip();
    const codes: number[] = [];
    for (let i = 0; i < 11; i++)
      codes.push(
        (await app.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress })).statusCode,
      );
    expect(codes.slice(0, 10).every((c) => c === 200)).toBe(true);
    const limited = await app.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress });
    expect([codes[10], limited.statusCode]).toEqual([429, 429]);
    expect(limited.json()).toEqual({ code: "RATE_LIMITED" });

    // recorder budget is per key and counted after auth: a forged request doesn't spend it
    const { key } = await setup();
    const other = (await setup()).key;
    const cfg = (k: string) => rec(k, "GET", "/v1/recorder/config");
    const remaining = (r: { headers: Record<string, unknown> }) =>
      Number(r.headers["x-ratelimit-remaining"]);
    const first = await cfg(key.key);
    expect(first.headers["x-ratelimit-limit"]).toBe("200");
    expect(first.headers["x-content-type-options"]).toBe("nosniff");
    expect(first.headers["strict-transport-security"]).toMatch(/max-age=/);
    const forged = await cfg(key.key.replace(/.$/, (c: string) => (c === "0" ? "1" : "0")));
    expect(forged.statusCode).toBe(401);
    expect(remaining(await cfg(key.key))).toBe(remaining(first) - 1);
    expect(remaining(await cfg(other.key))).toBe(199);
  });
});
