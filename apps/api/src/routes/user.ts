// L8 §4.1–§4.3 (v0): SIWE auth, orgs, agents (+ watch-key provisioning), recorder keys.
import { randomBytes } from "node:crypto";
import { agentKey } from "@afr/core";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { type Hex, verifyMessage } from "viem";
import { generateSiweNonce, parseSiweMessage, validateSiweMessage } from "viem/siwe";
import { z } from "zod";
import { newRecorderKey } from "../auth/recorder.js";
import {
  ApiError,
  type ApiOptions,
  bufHex,
  CSRF_COOKIE,
  hexBuf,
  type RequireUser,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  sha256,
} from "../http.js";

const NONCE_TTL_MS = 10 * 60_000;
const WRITE_ROLES = ["owner", "admin", "engineer"];

const Siwe = z.strictObject({
  message: z.string().max(4096),
  signature: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
});
const OrgCreate = z.strictObject({ name: z.string().min(1).max(200) });
const AgentCreate = z.strictObject({
  agent_id: z.string().min(1).max(200),
  name: z.string().min(1).max(200),
  privacy_level: z.union([z.literal(0), z.literal(1), z.literal(2)]).default(0),
  retention_days: z.number().int().positive().max(36_500).default(365),
  approval_threshold_cents: z
    .string()
    .regex(/^\d{1,18}$/)
    .optional(),
});
const KeyCreate = z.strictObject({
  lanes: z.array(z.number().int().min(0).max(65_535)).min(1).max(64).default([0]),
});
const OrgParam = z.strictObject({ org: z.uuid() });
const AgentParam = z.strictObject({ id: z.uuid() });
const KeyParam = z.strictObject({ id: z.uuid(), keyId: z.string().regex(/^[0-9a-f]{16}$/) });

interface AgentRow {
  id: string;
  org_id: string;
  agent_id: string;
  agent_key: Buffer;
  name: string;
  privacy_level: number;
  retention_days: number;
  approval_threshold_cents: string | null;
  status: string;
}
const agentJson = (a: AgentRow) => ({
  id: a.id,
  org_id: a.org_id,
  agent_id: a.agent_id,
  agent_key: bufHex(a.agent_key),
  name: a.name,
  privacy_level: a.privacy_level,
  retention_days: a.retention_days,
  approval_threshold_cents: a.approval_threshold_cents,
  status: a.status,
});

export const userRoutes: FastifyPluginAsync<
  ApiOptions & { now: () => number; requireUser: RequireUser }
> = async (app, o) => {
  const { pool, now } = o;
  const ts = (ms: number) => new Date(ms);
  const userOf = (req: FastifyRequest) => req.user as NonNullable<FastifyRequest["user"]>;
  const auth = { preHandler: o.requireUser };

  const audit = (req: FastifyRequest, orgId: string | null, action: string, target?: string) =>
    pool.query(
      "INSERT INTO audit_log (org_id, actor, action, target, ip) VALUES ($1, $2, $3, $4, $5)",
      [orgId, `user:${userOf(req).id}`, action, target ?? null, req.ip],
    );

  /** The caller's role in an org; 404 (not 403) for non-members, so ids don't leak across tenants. */
  const roleIn = async (orgId: string, userId: string, write = false) => {
    const { rows } = await pool.query<{ role: string }>(
      "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
      [orgId, userId],
    );
    const role = rows[0]?.role;
    if (!role) throw new ApiError(404, "NOT_FOUND");
    if (write && !WRITE_ROLES.includes(role)) throw new ApiError(403, "FORBIDDEN");
    return role;
  };
  const agentFor = async (id: string, userId: string, write = false) => {
    const { rows } = await pool.query<AgentRow>("SELECT * FROM agents WHERE id = $1", [id]);
    const a = rows[0];
    if (!a) throw new ApiError(404, "NOT_FOUND");
    await roleIn(a.org_id, userId, write);
    return a;
  };
  const tx = async <T>(fn: (q: Pick<typeof pool, "query">) => Promise<T>): Promise<T> => {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  };

  // ── §4.1 auth ──
  app.get("/v1/auth/nonce", async () => {
    const nonce = generateSiweNonce();
    await pool.query("INSERT INTO siwe_nonces (nonce, expires_at) VALUES ($1, $2)", [
      nonce,
      ts(now() + NONCE_TTL_MS),
    ]);
    return { nonce };
  });

  app.post("/v1/auth/siwe", async (req, reply) => {
    const b = Siwe.parse(req.body);
    const msg = parseSiweMessage(b.message);
    if (!msg.address || !msg.nonce) throw new ApiError(401, "SIWE_INVALID");
    // nonces are single-use: consumed before verifying, so a failed attempt can't reuse one
    const used = await pool.query(
      "DELETE FROM siwe_nonces WHERE nonce = $1 AND expires_at > $2 RETURNING nonce",
      [msg.nonce, ts(now())],
    );
    if (!used.rowCount) throw new ApiError(401, "SIWE_NONCE");
    if (!validateSiweMessage({ message: msg, domain: o.siweDomain, time: ts(now()) }))
      throw new ApiError(401, "SIWE_INVALID");
    // shortcut: EOA signatures only; ERC-1271 smart-account wallets need an RPC client (P4 dashboard)
    const ok = await verifyMessage({
      address: msg.address,
      message: b.message,
      signature: b.signature as Hex,
    });
    if (!ok) throw new ApiError(401, "SIWE_SIGNATURE");
    const wallet = hexBuf(msg.address.toLowerCase());
    const { rows } = await pool.query<{ id: string }>(
      "INSERT INTO users (wallet) VALUES ($1) ON CONFLICT (wallet) DO UPDATE SET wallet = excluded.wallet RETURNING id",
      [wallet],
    );
    const userId = rows[0]?.id as string;
    const token = randomBytes(32).toString("hex");
    const csrf = randomBytes(32).toString("hex");
    await pool.query(
      "INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at) VALUES ($1, $2, $3, $4)",
      [sha256(token), userId, sha256(csrf), ts(now() + SESSION_TTL_MS)],
    );
    const base = {
      path: "/",
      secure: true,
      sameSite: "strict" as const,
      maxAge: SESSION_TTL_MS / 1000,
    };
    reply.setCookie(SESSION_COOKIE, token, { ...base, httpOnly: true });
    reply.setCookie(CSRF_COOKIE, csrf, base); // readable by the dashboard, echoed as X-CSRF-Token
    return { user: { id: userId, wallet: bufHex(wallet) }, csrf };
  });

  app.post("/v1/auth/logout", auth, async (req, reply) => {
    await pool.query("DELETE FROM sessions WHERE token_hash = $1", [
      sha256(req.cookies[SESSION_COOKIE] as string),
    ]);
    reply.clearCookie(SESSION_COOKIE, { path: "/" }).clearCookie(CSRF_COOKIE, { path: "/" });
    return { ok: true };
  });

  app.get("/v1/me", auth, async (req) => {
    const u = userOf(req);
    const { rows } = await pool.query(
      "SELECT org_id, role FROM memberships WHERE user_id = $1 ORDER BY org_id",
      [u.id],
    );
    return { user: u, memberships: rows };
  });

  // ── §4.2 orgs ──
  app.get("/v1/orgs", auth, async (req) => {
    const { rows } = await pool.query(
      `SELECT o.id, o.name, o.plan, m.role FROM orgs o JOIN memberships m ON m.org_id = o.id
       WHERE m.user_id = $1 ORDER BY o.created_at`,
      [userOf(req).id],
    );
    return { orgs: rows };
  });

  app.post("/v1/orgs", auth, async (req, reply) => {
    const b = OrgCreate.parse(req.body);
    const id = await tx(async (q) => {
      const { rows } = await q.query<{ id: string }>(
        "INSERT INTO orgs (name) VALUES ($1) RETURNING id",
        [b.name],
      );
      const org = rows[0]?.id as string;
      await q.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')", [
        org,
        userOf(req).id,
      ]);
      return org;
    });
    await audit(req, id, "org.create", id);
    return reply.status(201).send({ id, name: b.name, role: "owner" });
  });

  app.get("/v1/orgs/:org", auth, async (req) => {
    const { org } = OrgParam.parse(req.params);
    const role = await roleIn(org, userOf(req).id);
    const { rows } = await pool.query("SELECT id, name, plan, region FROM orgs WHERE id = $1", [
      org,
    ]);
    return { ...rows[0], role };
  });

  // ── §4.3 agents ──
  app.get("/v1/orgs/:org/agents", auth, async (req) => {
    const { org } = OrgParam.parse(req.params);
    await roleIn(org, userOf(req).id);
    const { rows } = await pool.query<AgentRow>(
      "SELECT * FROM agents WHERE org_id = $1 ORDER BY created_at",
      [org],
    );
    return { agents: rows.map(agentJson) };
  });

  app.post("/v1/orgs/:org/agents", auth, async (req, reply) => {
    const { org } = OrgParam.parse(req.params);
    const b = AgentCreate.parse(req.body);
    await roleIn(org, userOf(req).id, true);
    let key: Hex;
    try {
      key = agentKey(b.agent_id);
    } catch {
      throw new ApiError(400, "AGENT_ID_INVALID");
    }
    // L4 §10 watch key: returned once (for the recorder config), stored only wrapped
    const watchKey = randomBytes(32);
    try {
      const a = await tx(async (q) => {
        const { rows } = await q.query<AgentRow>(
          `INSERT INTO agents (org_id, agent_id, agent_key, name, privacy_level, retention_days, approval_threshold_cents)
           VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING *`,
          [
            org,
            b.agent_id,
            hexBuf(key),
            b.name,
            b.privacy_level,
            b.retention_days,
            b.approval_threshold_cents ?? null,
          ],
        );
        const row = rows[0];
        if (!row) throw new ApiError(409, "AGENT_EXISTS");
        await q.query("INSERT INTO watch_keys (agent_id, kms_ciphertext) VALUES ($1, $2)", [
          row.id,
          Buffer.from(o.keys.wrap(watchKey, hexBuf(key))),
        ]);
        return row;
      });
      await audit(req, org, "agent.create", a.id);
      return reply.status(201).send({ agent: agentJson(a), watch_key: bufHex(watchKey) });
    } finally {
      watchKey.fill(0);
    }
  });

  app.get("/v1/agents/:id", auth, async (req) => {
    const { id } = AgentParam.parse(req.params);
    return { agent: agentJson(await agentFor(id, userOf(req).id)) };
  });

  app.post("/v1/agents/:id/recorder-keys", auth, async (req, reply) => {
    const { id } = AgentParam.parse(req.params);
    const b = KeyCreate.parse(req.body ?? {});
    const a = await agentFor(id, userOf(req).id, true);
    const k = newRecorderKey();
    await pool.query(
      "INSERT INTO recorder_keys (id, org_id, agent_id, secret_hash, lanes, created_by) VALUES ($1, $2, $3, $4, $5, $6)",
      [k.id, a.org_id, a.id, k.secretHash, b.lanes, userOf(req).id],
    );
    await audit(req, a.org_id, "recorder_key.create", k.id);
    return reply.status(201).send({ id: k.id, key: k.token, lanes: b.lanes }); // shown once
  });

  app.delete("/v1/agents/:id/recorder-keys/:keyId", auth, async (req) => {
    const { id, keyId } = KeyParam.parse(req.params);
    const a = await agentFor(id, userOf(req).id, true);
    const r = await pool.query(
      "UPDATE recorder_keys SET revoked_at = $3 WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL",
      [keyId, a.id, ts(now())],
    );
    if (!r.rowCount) throw new ApiError(404, "NOT_FOUND");
    await audit(req, a.org_id, "recorder_key.revoke", keyId);
    return { ok: true };
  });
};
