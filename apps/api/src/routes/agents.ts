// L8 §4.3 agents: create (+ watch key), settings, recorder keys, watched addresses, and the read views
// (lanes, batch index, checkpoints). Every route resolves the agent's org, then runs inside `inOrg` (RLS).
import { randomBytes } from "node:crypto";
import { agentKey } from "@afr/core";
import type { Hex } from "viem";
import { z } from "zod";
import { newRecorderKey } from "../auth/recorder.js";
import { inOrg, type Q } from "../db/tenancy.js";
import {
  ADMIN_ROLES,
  ApiError,
  type ApiOptions,
  audit,
  bufHex,
  hexBuf,
  type RequireUser,
  requireRole,
  WRITE_ROLES,
  type ZodPlugin,
} from "../http.js";
import { Addr, AddrOut, AgentParam, Hex32, Lane, Ok, OrgParam, U64 } from "../schemas.js";
import type { OrgSecrets } from "../secrets.js";

const Cents = z.string().regex(/^\d{1,18}$/);
const Status = z.enum(["active", "paused", "archived"]);
const Limit = z.coerce.number().int().min(1).max(500).default(100);
const Iso = z.string();

const AgentCreate = z.strictObject({
  agent_id: z.string().min(1).max(200),
  name: z.string().min(1).max(200),
  privacy_level: z.union([z.literal(0), z.literal(1), z.literal(2)]).default(0),
  retention_days: z.number().int().positive().max(36_500).default(365),
  approval_threshold_cents: Cents.optional(),
});
// privacy / retention changes need a new signed AgentProfile (`profile_statement`), not a PATCH (§4.3)
const AgentPatch = z
  .strictObject({
    name: z.string().min(1).max(200).optional(),
    approval_threshold_cents: Cents.nullable().optional(),
    status: Status.optional(),
  })
  .refine((b) => Object.keys(b).length > 0, { message: "empty patch" });
const Agent = z.strictObject({
  id: z.uuid(),
  org_id: z.uuid(),
  agent_id: z.string(),
  agent_key: Hex32,
  name: z.string(),
  privacy_level: z.number().int(),
  retention_days: z.number().int(),
  approval_threshold_cents: Cents.nullable(),
  status: Status,
});
const KeyParam = AgentParam.extend({ keyId: z.string().regex(/^[0-9a-f]{16}$/) });
const WatchedKind = z.enum(["eoa", "smart_account", "safe", "session_key"]);
const Watched = z.strictObject({
  id: z.uuid(),
  chain_id: U64,
  address: AddrOut,
  kind: WatchedKind,
  since_block: U64.nullable(),
  source: z.string(),
  created_at: Iso,
});
const LaneView = z.strictObject({
  lane: Lane,
  last_seq: U64.nullable(),
  last_chain_root: Hex32.nullable(),
  last_batch_at: Iso.nullable(),
  last_heartbeat_at: Iso.nullable(),
  recorder_version: z.string().nullable(),
  pending_batches: z.number().int().nullable(),
  store_lag_s: z.number().int().nullable(),
});
const Batch = z.strictObject({
  lane: Lane,
  seq_from: U64,
  seq_to: U64,
  entity_key: Hex32,
  arkiv_tx: Hex32.nullable(),
  chain_root: Hex32,
  batch_root: Hex32,
  created_at: Iso,
});
const Checkpoint = z.strictObject({
  id: z.uuid(),
  lane: Lane,
  seq_to: U64,
  chain_root: Hex32,
  batch_entity: Hex32,
  status: z.enum(["pending", "validated", "anchored", "superseded", "rejected"]),
  received_at: Iso,
});

interface AgentRow {
  id: string;
  org_id: string;
  agent_id: string;
  agent_key: Buffer;
  name: string;
  privacy_level: number;
  retention_days: number;
  approval_threshold_cents: string | null;
  status: z.infer<typeof Status>;
}
const agentJson = (a: AgentRow): z.infer<typeof Agent> => ({
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
const iso = (d: Date | null) => d?.toISOString() ?? null;
const hexOrNull = (b: Buffer | null) => (b ? bufHex(b) : null);

export const agentRoutes: ZodPlugin<
  ApiOptions & { now: () => number; requireUser: RequireUser; secrets: OrgSecrets }
> = async (app, o) => {
  const { pool, now, secrets } = o;
  const auth = { preHandler: o.requireUser };
  const uid = (req: { user?: { id: string } }) => (req.user as { id: string }).id;

  const assigned = async (q: Q, agentId: string, userId: string) =>
    !!(
      await q.query("SELECT 1 FROM agent_auditors WHERE agent_id = $1 AND user_id = $2", [
        agentId,
        userId,
      ])
    ).rowCount;

  /** Resolves the agent's org (system lookup), then runs `fn` scoped to it after the role check. */
  const withAgent = async <T>(
    agentId: string,
    userId: string,
    roles: string[] | undefined,
    fn: (q: Q, a: AgentRow) => Promise<T>,
  ): Promise<T> => {
    const org = (
      await pool.query<{ org_id: string }>("SELECT org_id FROM agents WHERE id = $1", [agentId])
    ).rows[0]?.org_id;
    if (!org) throw new ApiError(404, "NOT_FOUND");
    return inOrg(pool, org, async (q) => {
      const role = await requireRole(q, org, userId, roles);
      const a = (await q.query<AgentRow>("SELECT * FROM agents WHERE id = $1", [agentId])).rows[0];
      if (!a || (role === "auditor" && !(await assigned(q, agentId, userId))))
        throw new ApiError(404, "NOT_FOUND");
      return fn(q, a);
    });
  };

  app.get(
    "/v1/orgs/:org/agents",
    {
      ...auth,
      schema: { params: OrgParam, response: { 200: z.strictObject({ agents: z.array(Agent) }) } },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        const role = await requireRole(q, req.params.org, uid(req));
        const { rows } = await q.query<AgentRow>(
          role === "auditor"
            ? `SELECT a.* FROM agents a JOIN agent_auditors x ON x.agent_id = a.id
               WHERE a.org_id = $1 AND x.user_id = $2 ORDER BY a.created_at`
            : "SELECT * FROM agents WHERE org_id = $1 ORDER BY created_at",
          role === "auditor" ? [req.params.org, uid(req)] : [req.params.org],
        );
        return { agents: rows.map(agentJson) };
      }),
  );

  app.post(
    "/v1/orgs/:org/agents",
    {
      ...auth,
      schema: {
        params: OrgParam,
        body: AgentCreate,
        response: { 201: z.strictObject({ agent: Agent, watch_key: Hex32 }) },
      },
    },
    async (req, reply) => {
      const org = req.params.org;
      const b = req.body;
      let key: Hex;
      try {
        key = agentKey(b.agent_id);
      } catch {
        throw new ApiError(400, "AGENT_ID_INVALID");
      }
      // L4 §10 watch key: returned once (for the recorder config), stored only sealed under the org's DEK
      const watchKey = randomBytes(32);
      try {
        const a = await inOrg(pool, org, async (q) => {
          await requireRole(q, org, uid(req), WRITE_ROLES);
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
          // the unique indexes see other orgs' rows too, so a taken agent_id conflicts even under RLS
          const row = rows[0];
          if (!row) throw new ApiError(409, "AGENT_EXISTS");
          await q.query("INSERT INTO watch_keys (agent_id, kms_ciphertext) VALUES ($1, $2)", [
            row.id,
            await secrets.seal(org, watchKey, hexBuf(key)),
          ]);
          await audit(q, req, org, "agent.create", row.id);
          return row;
        });
        return reply.status(201).send({ agent: agentJson(a), watch_key: bufHex(watchKey) });
      } finally {
        watchKey.fill(0);
      }
    },
  );

  app.get(
    "/v1/agents/:id",
    {
      ...auth,
      schema: { params: AgentParam, response: { 200: z.strictObject({ agent: Agent }) } },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), undefined, async (_q, a) => ({ agent: agentJson(a) })),
  );

  app.patch(
    "/v1/agents/:id",
    {
      ...auth,
      schema: {
        params: AgentParam,
        body: AgentPatch,
        response: { 200: z.strictObject({ agent: Agent }) },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        const b = req.body;
        const { rows } = await q.query<AgentRow>(
          `UPDATE agents SET
             name = CASE WHEN $2 THEN $3 ELSE name END,
             approval_threshold_cents = CASE WHEN $4 THEN $5::bigint ELSE approval_threshold_cents END,
             status = CASE WHEN $6 THEN $7 ELSE status END,
             updated_at = now()
           WHERE id = $1 RETURNING *`,
          [
            a.id,
            b.name !== undefined,
            b.name ?? null,
            b.approval_threshold_cents !== undefined,
            b.approval_threshold_cents ?? null,
            b.status !== undefined,
            b.status ?? null,
          ],
        );
        await audit(q, req, a.org_id, "agent.update", a.id);
        return { agent: agentJson(rows[0] as AgentRow) };
      }),
  );

  // ── recorder keys ──
  app.post(
    "/v1/agents/:id/recorder-keys",
    {
      ...auth,
      schema: {
        params: AgentParam,
        body: z
          .strictObject({ lanes: z.array(Lane).min(1).max(64).default([0]) })
          .default({ lanes: [0] }),
        response: {
          201: z.strictObject({ id: z.string(), key: z.string(), lanes: z.array(Lane) }),
        },
      },
    },
    async (req, reply) => {
      const k = newRecorderKey();
      await withAgent(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        await q.query(
          "INSERT INTO recorder_keys (id, org_id, agent_id, secret_hash, lanes, created_by) VALUES ($1, $2, $3, $4, $5, $6)",
          [k.id, a.org_id, a.id, k.secretHash, req.body.lanes, uid(req)],
        );
        await audit(q, req, a.org_id, "recorder_key.create", k.id);
      });
      return reply.status(201).send({ id: k.id, key: k.token, lanes: req.body.lanes }); // shown once
    },
  );

  app.delete(
    "/v1/agents/:id/recorder-keys/:keyId",
    { ...auth, schema: { params: KeyParam, response: { 200: Ok } } },
    async (req) =>
      withAgent(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        const r = await q.query(
          "UPDATE recorder_keys SET revoked_at = $3 WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL",
          [req.params.keyId, a.id, new Date(now())],
        );
        if (!r.rowCount) throw new ApiError(404, "NOT_FOUND");
        await audit(q, req, a.org_id, "recorder_key.revoke", req.params.keyId);
        return { ok: true as const };
      }),
  );

  // ── watched addresses (the watcher's input, L6 §2) ──
  interface WatchedRow {
    id: string;
    chain_id: string;
    address: Buffer;
    kind: z.infer<typeof WatchedKind>;
    since_block: string | null;
    source: string;
    created_at: Date;
  }
  const watchedJson = (r: WatchedRow) => ({
    ...r,
    address: bufHex(r.address),
    created_at: r.created_at.toISOString(),
  });

  app.get(
    "/v1/agents/:id/watched-addresses",
    {
      ...auth,
      schema: {
        params: AgentParam,
        response: { 200: z.strictObject({ addresses: z.array(Watched) }) },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), undefined, async (q, a) => {
        const { rows } = await q.query<WatchedRow>(
          `SELECT id, chain_id, address, kind, since_block, source, created_at FROM watched_addresses
           WHERE agent_id = $1 ORDER BY created_at`,
          [a.id],
        );
        return { addresses: rows.map(watchedJson) };
      }),
  );

  app.post(
    "/v1/agents/:id/watched-addresses",
    {
      ...auth,
      schema: {
        params: AgentParam,
        body: z.strictObject({
          chain_id: U64,
          address: Addr,
          kind: WatchedKind.default("eoa"),
          since_block: U64.optional(),
        }),
        response: { 200: Watched, 201: Watched },
      },
    },
    async (req, reply) => {
      const [status, row] = await withAgent(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        const b = req.body;
        const cols = "id, chain_id, address, kind, since_block, source, created_at";
        const ins = await q.query<WatchedRow>(
          `INSERT INTO watched_addresses (org_id, agent_id, chain_id, address, kind, since_block)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (agent_id, chain_id, address) DO NOTHING RETURNING ${cols}`,
          [a.org_id, a.id, b.chain_id, hexBuf(b.address), b.kind, b.since_block ?? null],
        );
        if (ins.rows[0]) {
          await audit(q, req, a.org_id, "watched_address.add", ins.rows[0].id);
          return [201, ins.rows[0]] as const;
        }
        // idempotent: the same (chain, address) again returns the existing row
        const { rows } = await q.query<WatchedRow>(
          `SELECT ${cols} FROM watched_addresses WHERE agent_id = $1 AND chain_id = $2 AND address = $3`,
          [a.id, b.chain_id, hexBuf(b.address)],
        );
        return [200, rows[0] as WatchedRow] as const;
      });
      // sent after COMMIT: a client must never see a row that might still roll back
      return reply.status(status).send(watchedJson(row));
    },
  );

  app.delete(
    "/v1/agents/:id/watched-addresses/:addrId",
    {
      ...auth,
      schema: { params: AgentParam.extend({ addrId: z.uuid() }), response: { 200: Ok } },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        const r = await q.query("DELETE FROM watched_addresses WHERE id = $1 AND agent_id = $2", [
          req.params.addrId,
          a.id,
        ]);
        if (!r.rowCount) throw new ApiError(404, "NOT_FOUND");
        await audit(q, req, a.org_id, "watched_address.remove", req.params.addrId);
        return { ok: true as const };
      }),
  );

  // ── read views (public data, verifiable against Arkiv) ──
  // ── auditor assignments (§2): owner/admin assign members whose role is auditor ──
  const Auditor = z.strictObject({ user_id: z.uuid(), wallet: AddrOut, added_at: Iso });
  app.get(
    "/v1/agents/:id/auditors",
    {
      ...auth,
      schema: {
        params: AgentParam,
        response: { 200: z.strictObject({ auditors: z.array(Auditor) }) },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), ADMIN_ROLES, async (q, a) => {
        const { rows } = await q.query<{ user_id: string; wallet: Buffer; added_at: Date }>(
          `SELECT x.user_id, u.wallet, x.added_at FROM agent_auditors x JOIN users u ON u.id = x.user_id
           WHERE x.agent_id = $1 ORDER BY x.added_at`,
          [a.id],
        );
        return {
          auditors: rows.map((r) => ({
            user_id: r.user_id,
            wallet: bufHex(r.wallet) as Hex,
            added_at: r.added_at.toISOString(),
          })),
        };
      }),
  );

  app.post(
    "/v1/agents/:id/auditors",
    {
      ...auth,
      schema: {
        params: AgentParam,
        body: z.strictObject({ user_id: z.uuid() }),
        response: { 200: Ok },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), ADMIN_ROLES, async (q, a) => {
        const role = (
          await q.query<{ role: string }>(
            "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
            [a.org_id, req.body.user_id],
          )
        ).rows[0]?.role;
        if (role !== "auditor") throw new ApiError(409, "NOT_AN_AUDITOR");
        await q.query(
          `INSERT INTO agent_auditors (org_id, agent_id, user_id, added_by) VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING`,
          [a.org_id, a.id, req.body.user_id, uid(req)],
        );
        await audit(q, req, a.org_id, "auditor.assign", `${a.id}:${req.body.user_id}`);
        return { ok: true as const };
      }),
  );

  app.delete(
    "/v1/agents/:id/auditors/:userId",
    {
      ...auth,
      schema: { params: AgentParam.extend({ userId: z.uuid() }), response: { 200: Ok } },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), ADMIN_ROLES, async (q, a) => {
        const r = await q.query("DELETE FROM agent_auditors WHERE agent_id = $1 AND user_id = $2", [
          a.id,
          req.params.userId,
        ]);
        if (!r.rowCount) throw new ApiError(404, "NOT_FOUND");
        await audit(q, req, a.org_id, "auditor.unassign", `${a.id}:${req.params.userId}`);
        return { ok: true as const };
      }),
  );

  app.get(
    "/v1/agents/:id/lanes",
    {
      ...auth,
      schema: {
        params: AgentParam,
        response: { 200: z.strictObject({ lanes: z.array(LaneView) }) },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), undefined, async (q, a) => {
        const { rows } = await q.query<{
          lane: number;
          last_seq: string | null;
          last_chain_root: Buffer | null;
          last_batch_at: Date | null;
          last_heartbeat_at: Date | null;
          recorder_version: string | null;
          heartbeat: { pending_batches?: number; store_lag_s?: number } | null;
        }>("SELECT * FROM agent_lanes WHERE agent_id = $1 ORDER BY lane", [a.id]);
        return {
          lanes: rows.map((r) => ({
            lane: r.lane,
            last_seq: r.last_seq,
            last_chain_root: hexOrNull(r.last_chain_root),
            last_batch_at: iso(r.last_batch_at),
            last_heartbeat_at: iso(r.last_heartbeat_at),
            recorder_version: r.recorder_version,
            pending_batches: r.heartbeat?.pending_batches ?? null,
            store_lag_s: r.heartbeat?.store_lag_s ?? null,
          })),
        };
      }),
  );

  app.get(
    "/v1/agents/:id/batches",
    {
      ...auth,
      schema: {
        params: AgentParam,
        querystring: z.strictObject({
          lane: z.coerce.number().pipe(Lane).default(0),
          from_seq: U64.default("0"),
          limit: Limit,
        }),
        response: {
          200: z.strictObject({ batches: z.array(Batch), next_from_seq: U64.nullable() }),
        },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), undefined, async (q, a) => {
        const { lane, from_seq, limit } = req.query;
        const { rows } = await q.query<{
          lane: number;
          seq_from: string;
          seq_to: string;
          entity_key: Buffer;
          arkiv_tx: Buffer | null;
          chain_root: Buffer;
          batch_root: Buffer;
          created_at: Date;
        }>(
          `SELECT lane, seq_from, seq_to, entity_key, arkiv_tx, chain_root, batch_root, created_at
           FROM batches_index WHERE agent_id = $1 AND lane = $2 AND seq_from >= $3
           ORDER BY seq_from LIMIT $4`,
          [a.id, lane, from_seq, limit],
        );
        const last = rows.at(-1);
        return {
          batches: rows.map((r) => ({
            ...r,
            entity_key: bufHex(r.entity_key),
            arkiv_tx: hexOrNull(r.arkiv_tx),
            chain_root: bufHex(r.chain_root),
            batch_root: bufHex(r.batch_root),
            created_at: r.created_at.toISOString(),
          })),
          next_from_seq:
            rows.length === limit && last ? (BigInt(last.seq_to) + 1n).toString() : null,
        };
      }),
  );

  app.get(
    "/v1/agents/:id/checkpoints",
    {
      ...auth,
      schema: {
        params: AgentParam,
        querystring: z.strictObject({
          lane: z.coerce.number().pipe(Lane).default(0),
          after_seq: U64.optional(),
          limit: Limit,
        }),
        response: {
          200: z.strictObject({ checkpoints: z.array(Checkpoint), next_after_seq: U64.nullable() }),
        },
      },
    },
    async (req) =>
      withAgent(req.params.id, uid(req), undefined, async (q, a) => {
        const { lane, after_seq, limit } = req.query;
        const { rows } = await q.query<{
          id: string;
          lane: number;
          seq_to: string;
          chain_root: Buffer;
          batch_entity: Buffer;
          status: z.infer<typeof Checkpoint>["status"];
          received_at: Date;
        }>(
          `SELECT id, lane, seq_to, chain_root, batch_entity, status, received_at FROM checkpoints
           WHERE agent_id = $1 AND lane = $2 AND ($3::numeric IS NULL OR seq_to > $3::numeric)
           ORDER BY seq_to LIMIT $4`,
          [a.id, lane, after_seq ?? null, limit],
        );
        const last = rows.at(-1);
        return {
          checkpoints: rows.map((r) => ({
            ...r,
            chain_root: bufHex(r.chain_root),
            batch_entity: bufHex(r.batch_entity),
            received_at: r.received_at.toISOString(),
          })),
          next_after_seq: rows.length === limit && last ? last.seq_to : null,
        };
      }),
  );
};
