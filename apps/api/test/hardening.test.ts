// L8 hardening: CORS (§8), shared rate limits on Redis (§7), invitation list/revoke/email (§4.2), auditor
// assignments (§2), DEK cache eviction and the legacy master-key migration (§8).
// Needs AFR_PG_URL; Redis and Mailpit parts also AFR_REDIS_URL / AFR_SMTP_URL (pnpm local:up).
import { randomBytes } from "node:crypto";
import { aesGcmSeal } from "@afr/crypto";
import { Redis } from "ioredis";
import pg from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  buildServer,
  type KeyWrapper,
  localKeyWrapper,
  type Mailer,
  type MailMessage,
  migrate,
  migrateLegacySecrets,
  OrgSecrets,
  smtpMailer,
} from "../src/index.js";

const URL = process.env.AFR_PG_URL;
const REDIS = process.env.AFR_REDIS_URL;
const SMTP = process.env.AFR_SMTP_URL;
const DOMAIN = "app.afr.test";
const ORIGIN = `https://${DOMAIN}`;
const AGENT_PREFIX = "eip155:84532:0x00000000000000000000000000000000000a8004:";
const ip = () => `10.${randomBytes(3).join(".")}`;

describe.skipIf(!URL)("apps/api hardening", () => {
  const schema = `afr_api_hard_${randomBytes(4).toString("hex")}`;
  const masterKey = randomBytes(32);
  const sent: MailMessage[] = [];
  // records every message, and also delivers it to Mailpit when one is running
  const smtp = SMTP ? smtpMailer(SMTP, "afr@afr.test") : undefined;
  const mailer: Mailer = {
    async send(m) {
      sent.push(m);
      await smtp?.send(m);
    },
  };
  let pool: pg.Pool;
  let redis: Redis | undefined;
  let app: Awaited<ReturnType<typeof buildServer>>;

  const server = () =>
    buildServer({
      pool,
      siweDomain: DOMAIN,
      keys: localKeyWrapper(masterKey),
      dashboardOrigin: ORIGIN,
      mailer,
      ...(redis ? { redis } : {}),
    });

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 4, options: `-c search_path=${schema}` });
    await migrate(pool);
    if (REDIS) redis = new Redis(REDIS, { maxRetriesPerRequest: 1 });
    app = await server();
  });
  afterAll(async () => {
    await app?.close();
    redis?.disconnect();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  async function login(on = app) {
    const acct = privateKeyToAccount(generatePrivateKey());
    const remoteAddress = ip();
    const { nonce } = (
      await on.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress })
    ).json();
    const message = createSiweMessage({
      address: acct.address,
      chainId: 8453,
      domain: DOMAIN,
      nonce,
      uri: ORIGIN,
      version: "1",
    });
    const res = await on.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message, signature: await acct.signMessage({ message }) },
      remoteAddress,
    });
    expect(res.statusCode).toBe(200);
    const cookie = res.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    return {
      acct,
      id: res.json().user.id as string,
      get: { cookie },
      headers: { cookie, "x-csrf-token": res.json().csrf as string },
    };
  }
  type User = Awaited<ReturnType<typeof login>>;

  const call = (by: User, method: "GET" | "POST" | "DELETE", url: string, payload?: object) =>
    app.inject({
      method,
      url,
      headers: method === "GET" ? by.get : by.headers,
      ...(payload ? { payload } : {}),
    });

  async function org(u: User) {
    return (await call(u, "POST", "/v1/orgs", { name: "Acme" })).json().id as string;
  }
  async function agent(u: User, orgId: string) {
    const r = await call(u, "POST", `/v1/orgs/${orgId}/agents`, {
      agent_id: `${AGENT_PREFIX}${randomBytes(3).readUIntBE(0, 3)}`,
      name: "a",
    });
    expect(r.statusCode).toBe(201);
    return r.json().agent.id as string;
  }

  test("CORS: the dashboard origin only, with credentials", async () => {
    const pre = (origin: string) =>
      app.inject({
        method: "OPTIONS",
        url: "/v1/orgs",
        headers: { origin, "access-control-request-method": "POST" },
      });
    const ok = await pre(ORIGIN);
    expect(ok.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(ok.headers["access-control-allow-credentials"]).toBe("true");
    expect((await pre("https://evil.example")).headers["access-control-allow-origin"]).toBe(
      undefined,
    );
    const noOrigin = await buildServer({
      pool,
      siweDomain: DOMAIN,
      keys: localKeyWrapper(masterKey),
    });
    const r = await noOrigin.inject({
      method: "GET",
      url: "/v1/auth/nonce",
      headers: { origin: ORIGIN },
    });
    expect(r.headers["access-control-allow-origin"]).toBe(undefined);
    await noOrigin.close();
  });

  test.skipIf(!REDIS)("§7: two instances share one Redis budget", async () => {
    const other = await server();
    const remoteAddress = ip();
    const nonce = (on: typeof app) =>
      on.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await nonce(app)).statusCode);
    for (let i = 0; i < 5; i++) codes.push((await nonce(other)).statusCode);
    expect(codes.every((c) => c === 200)).toBe(true);
    expect((await nonce(app)).statusCode).toBe(429); // the 11th, counted across both
    await other.close();
  });

  test("invitations: emailed with the token in the link fragment; listed; revoked can't be accepted", async () => {
    const owner = await login();
    const o = await org(owner);
    const email = `inv-${randomBytes(4).toString("hex")}@afr.test`;
    const res = await call(owner, "POST", `/v1/orgs/${o}/invitations`, { role: "viewer", email });
    expect(res.statusCode).toBe(201);
    const { id, token, email_sent } = res.json();
    expect(email_sent).toBe(true);
    expect(sent.find((x) => x.to === email)?.text).toContain(`${ORIGIN}/invite#${token}`);
    const plain = await call(owner, "POST", `/v1/orgs/${o}/invitations`, { role: "viewer" });
    expect(plain.json().email_sent).toBe(false);

    const list = (await call(owner, "GET", `/v1/orgs/${o}/invitations`)).json().invitations;
    expect(list.map((i: { id: string }) => i.id).sort()).toEqual([id, plain.json().id].sort());
    expect(JSON.stringify(list)).not.toContain(token);
    expect(list.find((i: { id: string }) => i.id === id).email).toBe(email);

    expect((await call(owner, "DELETE", `/v1/orgs/${o}/invitations/${id}`)).statusCode).toBe(200);
    expect((await call(owner, "DELETE", `/v1/orgs/${o}/invitations/${id}`)).statusCode).toBe(404);
    const invitee = await login();
    expect((await call(invitee, "POST", "/v1/invitations/accept", { token })).statusCode).toBe(404);
    expect((await call(owner, "GET", `/v1/orgs/${o}/invitations`)).json().invitations).toHaveLength(
      1,
    );
    const audits = await pool.query(
      "SELECT 1 FROM audit_log WHERE org_id = $1 AND action = 'invitation.revoke'",
      [o],
    );
    expect(audits.rowCount).toBe(1);
  });

  test("invitations: a failing mailer still creates the invitation", async () => {
    const failing = await buildServer({
      pool,
      siweDomain: DOMAIN,
      keys: localKeyWrapper(masterKey),
      dashboardOrigin: ORIGIN,
      mailer: {
        send: () => Promise.reject(Object.assign(new Error("x"), { code: "ECONNREFUSED" })),
      },
    });
    const owner = await login(failing);
    const o = (
      await failing.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: owner.headers,
        payload: { name: "B" },
      })
    ).json().id;
    const r = await failing.inject({
      method: "POST",
      url: `/v1/orgs/${o}/invitations`,
      headers: owner.headers,
      payload: { role: "viewer", email: "x@afr.test" },
    });
    expect(r.statusCode).toBe(201);
    expect(r.json().email_sent).toBe(false);
    await failing.close();
  });

  test("auditors: see only assigned agents; no member list; assignments dropped with the role", async () => {
    const owner = await login();
    const o = await org(owner);
    const a = await agent(owner, o);
    const b = await agent(owner, o);
    const aud = await login();
    const eng = await login();
    await call(owner, "POST", `/v1/orgs/${o}/members`, {
      wallet: aud.acct.address,
      role: "auditor",
    });
    await call(owner, "POST", `/v1/orgs/${o}/members`, {
      wallet: eng.acct.address,
      role: "engineer",
    });
    const agents = async () =>
      (await call(aud, "GET", `/v1/orgs/${o}/agents`))
        .json()
        .agents.map((x: { id: string }) => x.id);

    expect(await agents()).toEqual([]);
    expect((await call(aud, "GET", `/v1/agents/${a}`)).statusCode).toBe(404);
    expect((await call(aud, "GET", `/v1/orgs/${o}/members`)).statusCode).toBe(403);
    expect((await call(aud, "GET", `/v1/orgs/${o}/invitations`)).statusCode).toBe(403);

    const assign = (by: User, agentId: string, userId: string) =>
      call(by, "POST", `/v1/agents/${agentId}/auditors`, { user_id: userId });
    expect((await assign(owner, a, aud.id)).statusCode).toBe(200);
    expect((await assign(owner, a, aud.id)).statusCode).toBe(200); // idempotent
    expect((await assign(owner, a, eng.id)).json()).toEqual({ code: "NOT_AN_AUDITOR" });
    expect((await assign(eng, b, aud.id)).statusCode).toBe(403);
    expect(await agents()).toEqual([a]);
    expect((await call(aud, "GET", `/v1/agents/${a}`)).statusCode).toBe(200);
    expect((await call(aud, "GET", `/v1/agents/${a}/lanes`)).statusCode).toBe(200);
    expect((await call(aud, "GET", `/v1/agents/${b}`)).statusCode).toBe(404);
    const listed = (await call(owner, "GET", `/v1/agents/${a}/auditors`)).json().auditors;
    expect(listed.map((x: { user_id: string }) => x.user_id)).toEqual([aud.id]);

    await assign(owner, b, aud.id);
    const unassign = () => call(owner, "DELETE", `/v1/agents/${b}/auditors/${aud.id}`);
    expect((await unassign()).statusCode).toBe(200);
    expect((await unassign()).statusCode).toBe(404);
    // a role change away from auditor drops their assignments
    await call(owner, "POST", `/v1/orgs/${o}/members`, {
      wallet: aud.acct.address,
      role: "viewer",
    });
    const left = await pool.query("SELECT 1 FROM agent_auditors WHERE user_id = $1", [aud.id]);
    expect(left.rowCount).toBe(0);
    expect(await agents()).toEqual([a, b]); // a viewer sees every agent
  });

  /** A KEK that counts unwraps. */
  const counting = () => {
    const inner = localKeyWrapper(masterKey);
    const n = { unwraps: 0 };
    const kek: KeyWrapper = {
      wrapDataKey: inner.wrapDataKey,
      unwrapDataKey: (w, id) => {
        n.unwraps++;
        return inner.unwrapDataKey(w, id);
      },
    };
    return { kek, n };
  };
  const newOrg = async () =>
    (await pool.query<{ id: string }>("INSERT INTO orgs (name) VALUES ('x') RETURNING id")).rows[0]
      ?.id as string;

  test("§8 DEK cache: LRU beyond maxCached, re-unwrapped after the TTL", async () => {
    const { kek, n } = counting();
    const clock = { now: 0 };
    const s = new OrgSecrets(pool, kek, { maxCached: 2, ttlMs: 1000, now: () => clock.now });
    const x = await newOrg();
    const y = await newOrg();
    const z = await newOrg();
    const touch = (org: string) => s.seal(org, new Uint8Array(4), new Uint8Array(1));
    await touch(x);
    await touch(y);
    await touch(x); // x is now the most recent
    expect(n.unwraps).toBe(2);
    await touch(z); // evicts y
    await touch(x);
    expect(n.unwraps).toBe(3);
    await touch(y);
    expect(n.unwraps).toBe(4);
    clock.now += 1000;
    await touch(y); // expired
    expect(n.unwraps).toBe(5);
  });

  test("§8 legacy secrets: master-key ciphertext re-sealed per org; idempotent", async () => {
    const owner = await login();
    const o = await org(owner);
    const a = await agent(owner, o);
    const legacyMasterKey = randomBytes(32);
    const ak = (
      await pool.query<{ agent_key: Buffer }>("SELECT agent_key FROM agents WHERE id = $1", [a])
    ).rows[0]?.agent_key as Buffer;
    const plain = randomBytes(32);
    const iv = randomBytes(12);
    const legacy = Buffer.concat([iv, aesGcmSeal(legacyMasterKey, iv, plain, ak)]);
    await pool.query("UPDATE watch_keys SET kms_ciphertext = $2 WHERE agent_id = $1", [a, legacy]);
    const secrets = new OrgSecrets(pool, localKeyWrapper(masterKey));

    const first = await migrateLegacySecrets({ pool, secrets, legacyMasterKey });
    expect(first).toMatchObject({ migrated: 1, failed: 0 });
    const sealed = (
      await pool.query<{ c: Buffer }>(
        "SELECT kms_ciphertext AS c FROM watch_keys WHERE agent_id = $1",
        [a],
      )
    ).rows[0]?.c as Buffer;
    expect(Buffer.from(await secrets.open(o, sealed, ak))).toEqual(plain);
    expect(await migrateLegacySecrets({ pool, secrets, legacyMasterKey })).toMatchObject({
      migrated: 0,
      failed: 0,
    });
  });
});
