// L8 §4.5 alerts (list, get with its events, ack / resolve / suppress) and §4.6 notification channels
// (webhook and email in v0; Slack, Telegram, PagerDuty later). The watcher raises alerts (L6 §6); state
// changes made here go to alert_events and, for a resolve, through afr_route_alert to the notifier.
// Channel configs (webhook URL + signing secret, email address) are sealed under the org's DEK, bound to the
// channel id, and never returned; a webhook's secret is shown once, on create.
import { randomBytes, randomUUID } from "node:crypto";
import { jcs } from "@afr/core";
import { z } from "zod";
import { inOrg, type Q } from "../db/tenancy.js";
import {
  ADMIN_ROLES,
  ApiError,
  type ApiOptions,
  audit,
  bufHex,
  type RequireUser,
  requireRole,
  WRITE_ROLES,
  type ZodPlugin,
} from "../http.js";
import { AddrOut, Hex32, Lane, Ok, OrgParam, U64 } from "../schemas.js";
import type { OrgSecrets } from "../secrets.js";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const Severity = z.enum(SEVERITIES);
const AlertStatus = z.enum(["open", "acked", "resolved", "suppressed"]);
const Resolution = z.enum(["fixed", "false_positive", "reorged", "late_intent", "expected"]);
/** Codes, hex, decimals and ISO times: no spaces, so no prose (W10). */
const Safe = z.string().regex(/^[A-Za-z0-9_.:,-]{0,400}$/);
const Iso = z.string();

// W10: the alert shape admits ids, hashes, seqs and codes only. Responses and webhook payloads are
// serialized through it, so anything else in subject/evidence fails instead of leaving the API.
const Subject = z.strictObject({
  chain_id: z.number().int().optional(),
  tx_hash: Hex32.optional(),
  seq_from: U64.optional(),
  seq_to: U64.optional(),
  address: AddrOut.optional(),
  batch_key: Hex32.optional(),
});
const Evidence = z.strictObject({
  last_records: z
    .array(z.strictObject({ seq: U64, hash: Hex32 }))
    .max(10)
    .optional(),
  explorer_url: z
    .string()
    .regex(/^https:\/\/[a-z0-9.-]+\/tx\/0x[0-9a-f]{64}$/)
    .optional(),
  details: z.record(z.string().regex(/^[a-z_]{1,32}$/), Safe).optional(),
});
export const Alert = z.strictObject({
  id: z.uuid(),
  org_id: z.uuid(),
  agent_id: z.uuid().nullable(),
  agent_key: Hex32.nullable(),
  lane: Lane.nullable(),
  type: z.string().regex(/^[A-Z_]{1,40}$/),
  severity: Severity,
  dedupe_key: Safe,
  status: AlertStatus,
  resolution: Resolution.nullable(),
  subject: Subject,
  evidence: Evidence,
  count: z.number().int(),
  first_seen_at: Iso,
  last_seen_at: Iso,
  suppressed_until: Iso.nullable(),
});
const AlertEvent = z.strictObject({
  kind: z.string(),
  actor: z.string(),
  data: z.record(z.string(), z.string()),
  at: Iso,
});
const IdParam = z.strictObject({ id: z.uuid() });
const OrgIdParam = OrgParam.extend({ id: z.uuid() });

export interface AlertRow {
  id: string;
  org_id: string;
  agent_id: string | null;
  agent_key: Buffer | null;
  lane: number | null;
  type: string;
  severity: z.infer<typeof Severity>;
  dedupe_key: string;
  status: z.infer<typeof AlertStatus>;
  resolution: z.infer<typeof Resolution> | null;
  subject: z.infer<typeof Subject>;
  evidence: z.infer<typeof Evidence>;
  count: number;
  first_seen_at: Date;
  last_seen_at: Date;
  suppressed_until: Date | null;
}
/** alerts joined with the agent's key. */
export const ALERT_SELECT =
  "SELECT al.*, g.agent_key FROM alerts al LEFT JOIN agents g ON g.id = al.agent_id";
export const alertJson = (r: AlertRow): z.infer<typeof Alert> => ({
  id: r.id,
  org_id: r.org_id,
  agent_id: r.agent_id,
  agent_key: r.agent_key ? bufHex(r.agent_key) : null,
  lane: r.lane,
  type: r.type,
  severity: r.severity,
  dedupe_key: r.dedupe_key,
  status: r.status,
  resolution: r.resolution,
  subject: r.subject,
  evidence: r.evidence,
  count: r.count,
  first_seen_at: r.first_seen_at.toISOString(),
  last_seen_at: r.last_seen_at.toISOString(),
  suppressed_until: r.suppressed_until?.toISOString() ?? null,
});

const ChannelKind = z.enum(["webhook", "email"]);
const ChannelCommon = {
  name: z.string().min(1).max(200),
  min_severity: Severity.default("high"),
  agent_filter: z.array(z.uuid()).min(1).max(100).nullable().default(null),
  enabled: z.boolean().default(true),
};
const ChannelCreate = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("webhook"), url: z.url().max(2000), ...ChannelCommon }),
  z.strictObject({ kind: z.literal("email"), to: z.email().max(320), ...ChannelCommon }),
]);
const ChannelPatch = z
  .strictObject({
    name: ChannelCommon.name.optional(),
    min_severity: Severity.optional(),
    agent_filter: z.array(z.uuid()).min(1).max(100).nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .refine((b) => Object.keys(b).length > 0, { message: "empty patch" });
const Channel = z.strictObject({
  id: z.uuid(),
  kind: ChannelKind,
  name: z.string(),
  min_severity: Severity,
  agent_filter: z.array(z.uuid()).nullable(),
  enabled: z.boolean(),
  created_at: Iso,
});
interface ChannelRow {
  id: string;
  org_id: string;
  kind: z.infer<typeof ChannelKind>;
  name: string;
  min_severity: z.infer<typeof Severity>;
  agent_filter: string[] | null;
  enabled: boolean;
  created_at: Date;
}
const channelJson = (c: ChannelRow): z.infer<typeof Channel> => ({
  id: c.id,
  kind: c.kind,
  name: c.name,
  min_severity: c.min_severity,
  agent_filter: c.agent_filter,
  enabled: c.enabled,
  created_at: c.created_at.toISOString(),
});
/** What a channel's config_kms holds (JCS). */
export type ChannelConfig =
  | { kind: "webhook"; url: string; secret: string }
  | { kind: "email"; to: string };
/** AAD for a channel's sealed config: the config can't be moved to another channel. */
export const channelAad = (id: string) => new TextEncoder().encode(`afr/channel/${id}`);

/** §4.10: https only (no credentials in the URL), plain http only when private targets are allowed (dev). */
export function webhookUrlOk(url: string, allowPrivate = false): boolean {
  try {
    const u = new URL(url);
    return (
      !u.username &&
      !u.password &&
      (u.protocol === "https:" || (allowPrivate && u.protocol === "http:"))
    );
  } catch {
    return false;
  }
}

export const alertRoutes: ZodPlugin<
  ApiOptions & { now: () => number; requireUser: RequireUser; secrets: OrgSecrets }
> = async (app, o) => {
  const { pool, now, secrets } = o;
  const auth = { preHandler: o.requireUser };
  const uid = (req: { user?: { id: string } }) => (req.user as { id: string }).id;

  const assigned = async (q: Q, agentId: string | null, userId: string) =>
    !!agentId &&
    !!(
      await q.query("SELECT 1 FROM agent_auditors WHERE agent_id = $1 AND user_id = $2", [
        agentId,
        userId,
      ])
    ).rowCount;

  /** Resolves the alert's org (system lookup), then runs `fn` scoped to it after the role check. */
  const withAlert = async <T>(
    id: string,
    userId: string,
    roles: string[] | undefined,
    fn: (q: Q, a: AlertRow) => Promise<T>,
  ): Promise<T> => {
    const org = (
      await pool.query<{ org_id: string }>("SELECT org_id FROM alerts WHERE id = $1", [id])
    ).rows[0]?.org_id;
    if (!org) throw new ApiError(404, "NOT_FOUND");
    return inOrg(pool, org, async (q) => {
      const role = await requireRole(q, org, userId, roles);
      const a = (await q.query<AlertRow>(`${ALERT_SELECT} WHERE al.id = $1 FOR UPDATE OF al`, [id]))
        .rows[0];
      if (!a || (role === "auditor" && !(await assigned(q, a.agent_id, userId))))
        throw new ApiError(404, "NOT_FOUND");
      return fn(q, a);
    });
  };
  const event = (q: Q, a: AlertRow, kind: string, userId: string, data: Record<string, string>) =>
    q.query(
      "INSERT INTO alert_events (org_id, alert_id, kind, actor, data) VALUES ($1, $2, $3, $4, $5)",
      [a.org_id, a.id, kind, `user:${userId}`, data],
    );
  const reload = async (q: Q, id: string) =>
    alertJson(
      (await q.query<AlertRow>(`${ALERT_SELECT} WHERE al.id = $1`, [id])).rows[0] as AlertRow,
    );

  // ── alerts ──
  app.get(
    "/v1/orgs/:org/alerts",
    {
      ...auth,
      schema: {
        params: OrgParam,
        querystring: z.strictObject({
          status: AlertStatus.optional(),
          severity: Severity.optional(),
          agent: z.uuid().optional(),
          type: z
            .string()
            .regex(/^[A-Z_]{1,40}$/)
            .optional(),
          limit: z.coerce.number().int().min(1).max(500).default(100),
        }),
        response: { 200: z.strictObject({ alerts: z.array(Alert) }) },
      },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        const role = await requireRole(q, req.params.org, uid(req));
        const f = req.query;
        const { rows } = await q.query<AlertRow>(
          `${ALERT_SELECT} WHERE al.org_id = $1
             AND ($2::text IS NULL OR al.status = $2) AND ($3::text IS NULL OR al.severity = $3)
             AND ($4::uuid IS NULL OR al.agent_id = $4) AND ($5::text IS NULL OR al.type = $5)
             AND ($6::uuid IS NULL OR al.agent_id IN (SELECT agent_id FROM agent_auditors WHERE user_id = $6))
           ORDER BY al.last_seen_at DESC LIMIT $7`,
          [
            req.params.org,
            f.status ?? null,
            f.severity ?? null,
            f.agent ?? null,
            f.type ?? null,
            role === "auditor" ? uid(req) : null,
            f.limit,
          ],
        );
        return { alerts: rows.map(alertJson) };
      }),
  );

  app.get(
    "/v1/alerts/:id",
    {
      ...auth,
      schema: {
        params: IdParam,
        response: { 200: z.strictObject({ alert: Alert, events: z.array(AlertEvent) }) },
      },
    },
    async (req) =>
      withAlert(req.params.id, uid(req), undefined, async (q, a) => {
        const { rows } = await q.query<{
          kind: string;
          actor: string;
          data: Record<string, string>;
          at: Date;
        }>("SELECT kind, actor, data, at FROM alert_events WHERE alert_id = $1 ORDER BY id", [
          a.id,
        ]);
        return {
          alert: alertJson(a),
          events: rows.map((e) => ({ ...e, at: e.at.toISOString() })),
        };
      }),
  );

  app.post(
    "/v1/alerts/:id/ack",
    { ...auth, schema: { params: IdParam, response: { 200: z.strictObject({ alert: Alert }) } } },
    async (req) =>
      withAlert(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        if (a.status === "resolved") throw new ApiError(409, "ALERT_RESOLVED");
        await q.query("UPDATE alerts SET status = 'acked', acked_by = $2 WHERE id = $1", [
          a.id,
          uid(req),
        ]);
        await event(q, a, "acked", uid(req), {});
        await audit(q, req, a.org_id, "alert.ack", a.id);
        return { alert: await reload(q, a.id) };
      }),
  );

  app.post(
    "/v1/alerts/:id/resolve",
    {
      ...auth,
      schema: {
        params: IdParam,
        body: z.strictObject({ resolution: Resolution, note: z.string().max(500).optional() }),
        response: { 200: z.strictObject({ alert: Alert }) },
      },
    },
    async (req) =>
      withAlert(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        if (a.status === "resolved") throw new ApiError(409, "ALERT_RESOLVED");
        await q.query(
          "UPDATE alerts SET status = 'resolved', resolution = $2, resolved_by = $3 WHERE id = $1",
          [a.id, req.body.resolution, uid(req)],
        );
        // the note is the user's own text: kept in the audit trail only, never in the alert or a payload
        await event(q, a, "resolved", uid(req), {
          resolution: req.body.resolution,
          ...(req.body.note ? { note: req.body.note } : {}),
        });
        await q.query("SELECT afr_route_alert($1, 'alert.resolved')", [a.id]);
        await audit(q, req, a.org_id, "alert.resolve", a.id);
        return { alert: await reload(q, a.id) };
      }),
  );

  app.post(
    "/v1/alerts/:id/suppress",
    {
      ...auth,
      schema: {
        params: IdParam,
        body: z.strictObject({ until: z.iso.datetime({ offset: true }) }),
        response: { 200: z.strictObject({ alert: Alert }) },
      },
    },
    async (req) => {
      const until = new Date(req.body.until);
      // in the future, at most 30 days: a forgotten suppression mustn't hide an agent for good
      if (until.getTime() <= now() || until.getTime() > now() + 30 * 86_400_000)
        throw new ApiError(400, "SUPPRESS_UNTIL_RANGE");
      return withAlert(req.params.id, uid(req), WRITE_ROLES, async (q, a) => {
        if (a.status === "resolved") throw new ApiError(409, "ALERT_RESOLVED");
        await q.query(
          "UPDATE alerts SET status = 'suppressed', suppressed_until = $2 WHERE id = $1",
          [a.id, until],
        );
        await event(q, a, "suppressed", uid(req), { until: until.toISOString() });
        await audit(q, req, a.org_id, "alert.suppress", a.id);
        return { alert: await reload(q, a.id) };
      });
    },
  );

  // ── notification channels ──
  const agentsInOrg = async (q: Q, org: string, ids: string[] | null | undefined) => {
    if (!ids) return;
    const { rows } = await q.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM agents WHERE org_id = $1 AND id = ANY ($2::uuid[])",
      [org, ids],
    );
    if (rows[0]?.n !== new Set(ids).size) throw new ApiError(400, "AGENT_FILTER_INVALID");
  };

  app.get(
    "/v1/orgs/:org/channels",
    {
      ...auth,
      schema: {
        params: OrgParam,
        response: { 200: z.strictObject({ channels: z.array(Channel) }) },
      },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        await requireRole(q, req.params.org, uid(req), WRITE_ROLES);
        const { rows } = await q.query<ChannelRow>(
          "SELECT * FROM notification_channels WHERE org_id = $1 ORDER BY created_at",
          [req.params.org],
        );
        return { channels: rows.map(channelJson) };
      }),
  );

  app.post(
    "/v1/orgs/:org/channels",
    {
      ...auth,
      schema: {
        params: OrgParam,
        body: ChannelCreate,
        response: { 201: z.strictObject({ channel: Channel, secret: z.string().optional() }) },
      },
    },
    async (req, reply) => {
      const org = req.params.org;
      const b = req.body;
      if (b.kind === "webhook" && !webhookUrlOk(b.url, o.allowPrivateWebhooks))
        throw new ApiError(400, "WEBHOOK_URL_INVALID");
      const id = randomUUID();
      const secret = b.kind === "webhook" ? `whsec_${randomBytes(32).toString("hex")}` : undefined;
      const config: ChannelConfig =
        b.kind === "webhook"
          ? { kind: "webhook", url: b.url, secret: secret as string }
          : { kind: "email", to: b.to };
      const c = await inOrg(pool, org, async (q) => {
        await requireRole(q, org, uid(req), ADMIN_ROLES);
        await agentsInOrg(q, org, b.agent_filter);
        const sealed = await secrets.seal(
          org,
          new TextEncoder().encode(jcs(config)),
          channelAad(id),
        );
        const row = (
          await q.query<ChannelRow>(
            `INSERT INTO notification_channels (id, org_id, kind, name, config_kms, min_severity, agent_filter, enabled)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [id, org, b.kind, b.name, sealed, b.min_severity, b.agent_filter, b.enabled],
          )
        ).rows[0] as ChannelRow;
        await audit(q, req, org, "channel.create", id);
        return row;
      });
      // the webhook secret is shown once
      return reply.status(201).send({ channel: channelJson(c), ...(secret ? { secret } : {}) });
    },
  );

  app.patch(
    "/v1/orgs/:org/channels/:id",
    {
      ...auth,
      schema: {
        params: OrgIdParam,
        body: ChannelPatch,
        response: { 200: z.strictObject({ channel: Channel }) },
      },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        await requireRole(q, req.params.org, uid(req), ADMIN_ROLES);
        const b = req.body;
        await agentsInOrg(q, req.params.org, b.agent_filter);
        const row = (
          await q.query<ChannelRow>(
            `UPDATE notification_channels SET name = coalesce($3, name), min_severity = coalesce($4, min_severity),
               agent_filter = CASE WHEN $5 THEN $6::uuid[] ELSE agent_filter END, enabled = coalesce($7, enabled)
             WHERE id = $1 AND org_id = $2 RETURNING *`,
            [
              req.params.id,
              req.params.org,
              b.name ?? null,
              b.min_severity ?? null,
              b.agent_filter !== undefined,
              b.agent_filter ?? null,
              b.enabled ?? null,
            ],
          )
        ).rows[0];
        if (!row) throw new ApiError(404, "NOT_FOUND");
        await audit(q, req, req.params.org, "channel.update", row.id);
        return { channel: channelJson(row) };
      }),
  );

  app.delete(
    "/v1/orgs/:org/channels/:id",
    { ...auth, schema: { params: OrgIdParam, response: { 200: Ok } } },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        await requireRole(q, req.params.org, uid(req), ADMIN_ROLES);
        const r = await q.query("DELETE FROM notification_channels WHERE id = $1 AND org_id = $2", [
          req.params.id,
          req.params.org,
        ]);
        if (!r.rowCount) throw new ApiError(404, "NOT_FOUND");
        await audit(q, req, req.params.org, "channel.delete", req.params.id);
        return { ok: true as const };
      }),
  );

  app.post(
    "/v1/channels/:id/test",
    {
      ...auth,
      schema: { params: IdParam, response: { 202: z.strictObject({ delivery_id: z.uuid() }) } },
    },
    async (req, reply) => {
      const org = (
        await pool.query<{ org_id: string }>(
          "SELECT org_id FROM notification_channels WHERE id = $1",
          [req.params.id],
        )
      ).rows[0]?.org_id;
      if (!org) throw new ApiError(404, "NOT_FOUND");
      const d = await inOrg(pool, org, async (q) => {
        await requireRole(q, org, uid(req), ADMIN_ROLES);
        const r = (
          await q.query<{ delivery_id: string }>(
            `INSERT INTO deliveries (org_id, channel_id, event) VALUES ($1, $2, 'channel.test')
             RETURNING delivery_id`,
            [org, req.params.id],
          )
        ).rows[0] as { delivery_id: string };
        await audit(q, req, org, "channel.test", req.params.id);
        return r;
      });
      return reply.status(202).send(d);
    },
  );
};
