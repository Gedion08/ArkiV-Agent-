// L8 §4.5/§4.6 alerts and channels, §5 notifier: lifecycle (ack / resolve / suppress) with tenancy and roles,
// channel configs sealed and never returned, P4 (webhook signatures verify with the documented algorithm,
// retries), W10 (no plaintext leaves in an alert), SSRF guard. Alerts are inserted as the watcher does
// (insert + afr_route_alert). Needs AFR_PG_URL (pnpm local:up); skipped without it.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  blockedAddress,
  buildServer,
  drainDeliveries,
  localKeyWrapper,
  type MailMessage,
  migrate,
  type NotifierOptions,
  OrgSecrets,
  RETRY_DELAYS_S,
} from "../src/index.js";

const URL = process.env.AFR_PG_URL;
const DOMAIN = "app.afr.test";
const AGENT_PREFIX = "eip155:84532:0x00000000000000000000000000000000000a8004:";
const ip = () => `10.${randomBytes(3).join(".")}`;
const TX = `0x${"ab".repeat(32)}`;

/** The documented receiver check (§4.10): HMAC-SHA256(secret, t + "." + body), constant-time, fresh t. */
function verifySignature(secret: string, header: string, body: string, nowS: number) {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header);
  if (!m || Math.abs(nowS - Number(m[1])) > 300) return false;
  const want = createHmac("sha256", secret).update(`${m[1]}.${body}`).digest();
  return timingSafeEqual(want, Buffer.from(m[2] as string, "hex"));
}

describe.skipIf(!URL)("alerts, channels, notifier", () => {
  const schema = `afr_alerts_test_${randomBytes(4).toString("hex")}`;
  let pool: pg.Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;
  const keys = localKeyWrapper(randomBytes(32));
  const hooks: { headers: IncomingHttpHeaders; body: string }[] = [];
  const statuses: number[] = [];
  const hookServer = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => {
      hooks.push({ headers: req.headers, body });
      res.statusCode = statuses.shift() ?? 200;
      res.end();
    });
  });
  let hookUrl = "";
  const mails: MailMessage[] = [];
  let notifier: NotifierOptions;

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: URL, max: 4, options: `-c search_path=${schema}` });
    await migrate(pool);
    app = await buildServer({ pool, siweDomain: DOMAIN, keys, allowPrivateWebhooks: true });
    await new Promise<void>((r) => hookServer.listen(0, "127.0.0.1", r));
    hookUrl = `http://127.0.0.1:${(hookServer.address() as AddressInfo).port}/hook`;
    notifier = {
      pool,
      secrets: new OrgSecrets(pool, keys),
      mailer: { send: async (m) => void mails.push(m) },
      dashboardOrigin: "https://app.afr.test",
      allowPrivateWebhooks: true,
    };
  });
  afterAll(async () => {
    hookServer.close();
    await app?.close();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

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
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message, signature: await acct.signMessage({ message }) },
      remoteAddress,
    });
    const cookie = res.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    return {
      acct,
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
    const agent = (
      await app.inject({
        method: "POST",
        url: `/v1/orgs/${org.id}/agents`,
        headers: u.headers,
        payload: {
          agent_id: `${AGENT_PREFIX}${randomBytes(3).readUIntBE(0, 3)}`,
          name: "treasury",
        },
      })
    ).json().agent;
    return { u, org: org.id as string, agent: agent.id as string };
  }

  /** As the watcher's PgAlerts does: insert, then route. */
  async function raise(
    org: string,
    agent: string,
    o: { type?: string; severity?: string; evidence?: unknown } = {},
  ) {
    const id = (
      await pool.query<{ id: string }>(
        `INSERT INTO alerts (org_id, agent_id, type, severity, dedupe_key, subject, evidence)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [
          org,
          agent,
          o.type ?? "UNLOGGED_TX",
          o.severity ?? "critical",
          `UNLOGGED_TX:84532:${randomBytes(32).toString("hex")}`,
          { chain_id: 84532, tx_hash: TX },
          o.evidence ?? { explorer_url: `https://sepolia.basescan.org/tx/${TX}` },
        ],
      )
    ).rows[0]?.id as string;
    await pool.query("SELECT afr_route_alert($1, 'alert.opened')", [id]);
    return id;
  }

  type Setup = Awaited<ReturnType<typeof setup>>;
  const createChannel = async (s: Setup, payload: object) => {
    const r = await app.inject({
      method: "POST",
      url: `/v1/orgs/${s.org}/channels`,
      headers: s.u.headers,
      payload,
    });
    expect(r.statusCode).toBe(201);
    return r.json() as { channel: { id: string }; secret?: string };
  };
  const deliveries = async (channel: string) =>
    (
      await pool.query(
        `SELECT event, status, attempts, last_error, next_at > now() AS later FROM deliveries
          WHERE channel_id = $1 ORDER BY id`,
        [channel],
      )
    ).rows;
  const post = (s: Setup, url: string, payload?: object) =>
    app.inject({ method: "POST", url, headers: s.u.headers, ...(payload ? { payload } : {}) });

  test("lifecycle: list/get, ack, suppress, resolve (audited, events); viewers read only; other orgs 404", async () => {
    const s = await setup();
    const id = await raise(s.org, s.agent);
    const list = await app.inject({
      method: "GET",
      url: `/v1/orgs/${s.org}/alerts?status=open`,
      headers: s.u.get,
    });
    expect(list.statusCode).toBe(200);
    expect(list.json().alerts).toMatchObject([
      {
        id,
        type: "UNLOGGED_TX",
        severity: "critical",
        status: "open",
        count: 1,
        subject: { tx_hash: TX },
      },
    ]);
    const other = await setup();
    expect((await post(other, `/v1/alerts/${id}/ack`)).statusCode).toBe(404);
    for (const url of [`/v1/alerts/${id}`, `/v1/orgs/${s.org}/alerts`])
      expect((await app.inject({ method: "GET", url, headers: other.u.get })).statusCode).toBe(404);

    const viewer = await login();
    await post(s, `/v1/orgs/${s.org}/members`, { wallet: viewer.acct.address, role: "viewer" });
    expect(
      (await app.inject({ method: "GET", url: `/v1/alerts/${id}`, headers: viewer.get }))
        .statusCode,
    ).toBe(200);
    expect(
      (await app.inject({ method: "POST", url: `/v1/alerts/${id}/ack`, headers: viewer.headers }))
        .statusCode,
    ).toBe(403);

    expect((await post(s, `/v1/alerts/${id}/ack`)).json().alert.status).toBe("acked");
    const tooLong = new Date(Date.now() + 31 * 86_400_000).toISOString();
    expect((await post(s, `/v1/alerts/${id}/suppress`, { until: tooLong })).statusCode).toBe(400);
    const until = new Date(Date.now() + 3_600_000).toISOString();
    expect((await post(s, `/v1/alerts/${id}/suppress`, { until })).json().alert).toMatchObject({
      status: "suppressed",
      suppressed_until: until,
    });
    const res = await post(s, `/v1/alerts/${id}/resolve`, {
      resolution: "false_positive",
      note: "funding top-up",
    });
    expect(res.json().alert).toMatchObject({ status: "resolved", resolution: "false_positive" });
    expect((await post(s, `/v1/alerts/${id}/resolve`, { resolution: "fixed" })).statusCode).toBe(
      409,
    );
    const got = (
      await app.inject({ method: "GET", url: `/v1/alerts/${id}`, headers: s.u.get })
    ).json();
    expect(got.events.map((e: { kind: string }) => e.kind)).toEqual([
      "acked",
      "suppressed",
      "resolved",
    ]);
    // the user's note stays in the audit trail, never in the alert itself
    expect(JSON.stringify(got.alert)).not.toContain("funding");
    const { rows } = await pool.query(
      "SELECT action FROM audit_log WHERE target = $1 ORDER BY id",
      [id],
    );
    expect(rows.map((r) => r.action)).toEqual(["alert.ack", "alert.suppress", "alert.resolve"]);
  });

  test("channels: admin only, config sealed and never returned, https unless private targets are allowed", async () => {
    const s = await setup();
    // a server without allowPrivateWebhooks (same DB, so the session works): http:// is rejected
    const strict = await buildServer({ pool, siweDomain: DOMAIN, keys });
    try {
      const r = await strict.inject({
        method: "POST",
        url: `/v1/orgs/${s.org}/channels`,
        headers: s.u.headers,
        payload: { kind: "webhook", name: "x", url: "http://hooks.example.com/afr" },
      });
      expect(r.json().code).toBe("WEBHOOK_URL_INVALID");
    } finally {
      await strict.close();
    }
    const hook = await createChannel(s, {
      kind: "webhook",
      name: "ops",
      url: hookUrl,
      min_severity: "high",
    });
    expect(hook.secret).toMatch(/^whsec_[0-9a-f]{64}$/);
    await createChannel(s, { kind: "email", name: "oncall", to: "oncall@acme.test" });
    const other = await setup();
    const bad = await post(s, `/v1/orgs/${s.org}/channels`, {
      kind: "email",
      name: "x",
      to: "x@acme.test",
      agent_filter: [other.agent],
    });
    expect(bad.json().code).toBe("AGENT_FILTER_INVALID");
    const list = await app.inject({
      method: "GET",
      url: `/v1/orgs/${s.org}/channels`,
      headers: s.u.get,
    });
    expect(list.json().channels.map((c: { kind: string }) => c.kind)).toEqual(["webhook", "email"]);
    for (const secret of [hook.secret as string, hookUrl, "oncall@acme.test"])
      expect(list.body).not.toContain(secret);
    const { rows } = await pool.query(
      "SELECT config_kms FROM notification_channels WHERE org_id = $1",
      [s.org],
    );
    for (const r of rows) expect(r.config_kms.toString("latin1")).not.toContain("oncall");

    const patched = await app.inject({
      method: "PATCH",
      url: `/v1/orgs/${s.org}/channels/${hook.channel.id}`,
      headers: s.u.headers,
      payload: { min_severity: "critical", enabled: false },
    });
    expect(patched.json().channel).toMatchObject({ min_severity: "critical", enabled: false });
    const del = (o: Setup) =>
      app.inject({
        method: "DELETE",
        url: `/v1/orgs/${o.org}/channels/${hook.channel.id}`,
        headers: o.u.headers,
      });
    expect((await del(other)).statusCode).toBe(404);
    expect((await del(s)).statusCode).toBe(200);
  });

  test("P4: routing by severity, signed webhook (documented algorithm), email, resolve notifies, test event", async () => {
    const s = await setup();
    const hook = await createChannel(s, {
      kind: "webhook",
      name: "ops",
      url: hookUrl,
      min_severity: "high",
    });
    const mail = await createChannel(s, {
      kind: "email",
      name: "oncall",
      to: "oncall@acme.test",
      min_severity: "critical",
    });
    hooks.length = 0;
    mails.length = 0;

    await raise(s.org, s.agent, { type: "ANCHOR_LAG", severity: "medium" }); // below both minimums
    const id = await raise(s.org, s.agent);
    await drainDeliveries(notifier);
    expect(await deliveries(hook.channel.id)).toMatchObject([
      { event: "alert.opened", status: "sent", attempts: 1 },
    ]);
    expect(await deliveries(mail.channel.id)).toMatchObject([{ status: "sent" }]);

    const h = hooks[0] as (typeof hooks)[0];
    const sig = String(h.headers["x-afr-signature"]);
    const nowS = Date.now() / 1000;
    expect(h.headers["x-afr-event"]).toBe("alert.opened");
    expect(h.headers["x-afr-delivery"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(verifySignature(hook.secret as string, sig, h.body, nowS)).toBe(true);
    expect(verifySignature("whsec_wrong", sig, h.body, nowS)).toBe(false);
    expect(verifySignature(hook.secret as string, sig, `${h.body} `, nowS)).toBe(false);
    expect(verifySignature(hook.secret as string, sig, h.body, nowS + 600)).toBe(false); // replayed late
    expect(JSON.parse(h.body)).toMatchObject({
      type: "alert.opened",
      alert: { id, type: "UNLOGGED_TX" },
      agent: { id: s.agent, name: "treasury" },
    });
    expect(mails).toHaveLength(1);
    expect(mails[0]).toMatchObject({
      to: "oncall@acme.test",
      subject: "[AFR] CRITICAL UNLOGGED_TX",
    });
    expect(mails[0]?.text).toContain(`https://app.afr.test/alerts/${id}`);

    await post(s, `/v1/alerts/${id}/resolve`, { resolution: "fixed" });
    const t = await post(s, `/v1/channels/${hook.channel.id}/test`);
    expect(t.statusCode).toBe(202);
    await drainDeliveries(notifier);
    expect(hooks.slice(1).map((x) => x.headers["x-afr-event"])).toEqual([
      "alert.resolved",
      "channel.test",
    ]);
    expect(JSON.parse(hooks[2]?.body as string)).toEqual({
      type: "channel.test",
      channel: { id: hook.channel.id, name: "ops" },
    });
  });

  test("retries: a 500 is rescheduled with backoff; the 10th failure is final", async () => {
    const s = await setup();
    const hook = await createChannel(s, {
      kind: "webhook",
      name: "ops",
      url: hookUrl,
      min_severity: "info",
    });
    await raise(s.org, s.agent);
    statuses.push(500);
    await drainDeliveries(notifier);
    expect(await deliveries(hook.channel.id)).toMatchObject([
      { status: "pending", attempts: 1, last_error: "HTTP_500", later: true },
    ]);
    // fast-forward to the last attempt
    await pool.query("UPDATE deliveries SET attempts = $2, next_at = now() WHERE channel_id = $1", [
      hook.channel.id,
      RETRY_DELAYS_S.length,
    ]);
    statuses.push(503);
    await drainDeliveries(notifier);
    expect(await deliveries(hook.channel.id)).toMatchObject([
      { status: "failed", attempts: 10, last_error: "HTTP_503" },
    ]);
  });

  test("W10: an alert carrying prose is never sent (PAYLOAD_SHAPE) and fails the API's response schema", async () => {
    const s = await setup();
    const hook = await createChannel(s, {
      kind: "webhook",
      name: "ops",
      url: hookUrl,
      min_severity: "info",
    });
    hooks.length = 0;
    const id = await raise(s.org, s.agent, {
      evidence: { details: { note: "CANARY transfer 5 ETH to bob" } },
    });
    await drainDeliveries(notifier);
    expect(await deliveries(hook.channel.id)).toMatchObject([
      { status: "failed", last_error: "PAYLOAD_SHAPE" },
    ]);
    expect(hooks).toEqual([]);
    const r = await app.inject({ method: "GET", url: `/v1/alerts/${id}`, headers: s.u.get });
    expect(r.statusCode).toBe(500);
    expect(r.body).not.toContain("CANARY");
  });

  test("SSRF guard: loopback, private, link-local (metadata) and mapped addresses are blocked", () => {
    for (const a of [
      "127.0.0.1",
      "10.1.2.3",
      "172.20.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "169.254.170.2",
      "::1",
      "fd00::1",
      "fe80::1",
      "::ffff:127.0.0.1",
      "0.0.0.0",
      "100.64.0.1",
    ])
      expect([a, blockedAddress(a)]).toEqual([a, true]);
    for (const a of ["8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1"])
      expect([a, blockedAddress(a)]).toEqual([a, false]);
  });
});
