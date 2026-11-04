// L8 §4.4 recorder endpoints (HMAC auth, §2). Notices are idempotent by (kind, agent, lane, seq) (L2 §10):
// a resent notice hits a unique key and changes nothing.
import { jcsData } from "@afr/core";
import type { FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import { checkRecorderRequest, RECORDER_KEY_RE } from "../auth/recorder.js";
import { inOrg } from "../db/tenancy.js";
import { ApiError, type ApiOptions, bufHex, hexBuf, sha256, type ZodPlugin } from "../http.js";
import { Addr, Hex32, Lane, Ok, U64 } from "../schemas.js";
import type { OrgSecrets } from "../secrets.js";

interface RecorderCtx {
  keyId: string;
  orgId: string;
  agentId: string;
  agentKey: string;
  lanes: number[];
  privacy: number;
  approvalThresholdCents: string | null;
}

declare module "fastify" {
  interface FastifyRequest {
    recorder?: RecorderCtx;
  }
}

/** §7: 50 req/s per key, burst 200. Counted after auth, so a forged request can't spend a key's budget. */
const RECORDER_LIMIT = {
  max: 200,
  timeWindow: 4000,
  hook: "preHandler" as const,
  keyGenerator: (req: FastifyRequest) => `rk:${req.recorder?.keyId ?? req.ip}`,
};

const agentKeyField = { agent_key: Hex32.optional() };

const Heartbeat = z.strictObject({
  ...agentKeyField,
  lane: Lane,
  next_seq: U64,
  pending_batches: z.number().int().min(0),
  store_lag_s: z.number().int().min(0),
  key_not_after: U64,
  version: z.string().max(64),
});
const Intents = z.strictObject({
  items: z
    .array(
      z.strictObject({
        ...agentKeyField,
        lane: Lane,
        seq: U64,
        chain_id: U64,
        tx_commit: Hex32.optional(),
        nonce_commit: Hex32,
      }),
    )
    .min(1)
    .max(100),
});
const Checkpoint = z.strictObject({
  ...agentKeyField,
  lane: Lane,
  seq_from: U64,
  seq_to: U64,
  batch_root: Hex32,
  chain_root: Hex32,
  entity_key: Hex32,
  arkiv_tx: Hex32.optional(),
});
const Delegation = z.strictObject({
  lane: Lane,
  session_key: Addr,
  not_before: U64,
  not_after: U64,
  entity_key: Hex32,
  presigned_revocation: z
    .string()
    .regex(/^0x[0-9a-fA-F]{130}$/)
    .optional(),
});
const Duplicate = z.strictObject({ duplicate: z.boolean() });
const Config = z.strictObject({
  readers: z.array(z.string()),
  policy: z.null(),
  approval_threshold_cents: z.string().nullable(),
  privacy_level: z.number().int(),
  /** Latest anchored checkpoint per lane of this key (P3-06): the recorder marks batches ≤ seq_to anchored. */
  anchored: z.array(
    z.strictObject({ lane: Lane, seq_to: U64, epoch: U64, anchor_tx: Hex32, chain_root: Hex32 }),
  ),
});

export const recorderRoutes: ZodPlugin<
  ApiOptions & { now: () => number; secrets: OrgSecrets }
> = async (app, o) => {
  const { pool, now, secrets } = o;
  const nowS = () => Math.floor(now() / 1000);

  const authenticate = async (req: FastifyRequest) => {
    const auth = req.headers.authorization ?? "";
    const m = RECORDER_KEY_RE.exec(auth.replace(/^Bearer /, ""));
    if (!m || !auth.startsWith("Bearer ")) throw new ApiError(401, "RECORDER_AUTH");
    // system lookup: the key, not a session, says which org this is
    const { rows } = await pool.query<{
      secret_hash: Buffer;
      org_id: string;
      agent_id: string;
      lanes: number[];
      agent_key: Buffer;
      privacy_level: number;
      approval_threshold_cents: string | null;
    }>(
      `SELECT k.secret_hash, k.org_id, k.agent_id, k.lanes, a.agent_key, a.privacy_level, a.approval_threshold_cents
       FROM recorder_keys k JOIN agents a ON a.id = k.agent_id
       WHERE k.id = $1 AND k.revoked_at IS NULL`,
      [m[1]],
    );
    const k = rows[0];
    const failure = k
      ? checkRecorderRequest(
          {
            method: req.method,
            path: req.url,
            body: req.rawBody ?? Buffer.alloc(0),
            secret: m[2] as string,
            ts: String(req.headers["x-afr-timestamp"] ?? ""),
            sig: String(req.headers["x-afr-signature"] ?? ""),
          },
          k.secret_hash,
          nowS(),
        )
      : "BAD_SECRET";
    // one code for every failure: don't tell a prober which part was wrong
    if (failure || !k) throw new ApiError(401, "RECORDER_AUTH");
    await pool.query("UPDATE recorder_keys SET last_used_at = now() WHERE id = $1", [m[1]]);
    req.recorder = {
      keyId: m[1] as string,
      orgId: k.org_id,
      agentId: k.agent_id,
      agentKey: bufHex(k.agent_key),
      lanes: k.lanes,
      privacy: k.privacy_level,
      approvalThresholdCents: k.approval_threshold_cents,
    };
  };

  const ctx = (req: FastifyRequest, lane?: number, agentKey?: string) => {
    const r = req.recorder as RecorderCtx;
    if (lane !== undefined && !r.lanes.includes(lane)) throw new ApiError(403, "LANE_FORBIDDEN");
    if (agentKey !== undefined && agentKey !== r.agentKey)
      throw new ApiError(403, "AGENT_MISMATCH");
    return r;
  };

  await app.register(async (plain) => {
    const r = plain.withTypeProvider<ZodTypeProvider>();
    r.addHook("preHandler", authenticate);
    const opts = { config: { rateLimit: RECORDER_LIMIT } };

    r.post(
      "/v1/recorder/heartbeat",
      { ...opts, schema: { body: Heartbeat, response: { 200: Ok } } },
      async (req) => {
        const b = req.body;
        const c = ctx(req, b.lane, b.agent_key);
        await inOrg(pool, c.orgId, (q) =>
          q.query(
            `INSERT INTO agent_lanes (agent_id, lane, last_heartbeat_at, recorder_version, heartbeat)
             VALUES ($1, $2, now(), $3, $4)
             ON CONFLICT (agent_id, lane) DO UPDATE SET last_heartbeat_at = now(),
               recorder_version = excluded.recorder_version, heartbeat = excluded.heartbeat`,
            [c.agentId, b.lane, b.version, b],
          ),
        );
        return { ok: true as const };
      },
    );

    r.post(
      "/v1/recorder/intents",
      {
        ...opts,
        schema: {
          body: Intents,
          response: { 200: z.strictObject({ accepted: z.number().int() }) },
        },
      },
      async (req) => {
        const c = ctx(req);
        for (const i of req.body.items) ctx(req, i.lane, i.agent_key);
        const accepted = await inOrg(pool, c.orgId, async (q) => {
          let n = 0;
          for (const i of req.body.items) {
            const res = await q.query(
              `INSERT INTO tx_intents (agent_id, lane, seq, chain_id, tx_commit, nonce_commit)
               VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
              [
                c.agentId,
                i.lane,
                i.seq,
                i.chain_id,
                i.tx_commit ? hexBuf(i.tx_commit) : null,
                hexBuf(i.nonce_commit),
              ],
            );
            n += res.rowCount ?? 0;
          }
          // the watcher reads the rows; the notification only wakes it (L6)
          if (n) await q.query("SELECT pg_notify('afr_intents', $1)", [c.agentId]);
          return n;
        });
        return { accepted };
      },
    );

    r.post(
      "/v1/recorder/checkpoints",
      {
        ...opts,
        schema: {
          body: Checkpoint,
          response: {
            200: Duplicate.extend({ status: z.literal("pending") }),
            201: Duplicate.extend({ status: z.literal("pending") }),
          },
        },
      },
      async (req, reply) => {
        const b = req.body;
        const c = ctx(req, b.lane, b.agent_key);
        if (BigInt(b.seq_from) > BigInt(b.seq_to)) throw new ApiError(400, "SEQ_RANGE");
        const inserted = await inOrg(pool, c.orgId, async (q) => {
          const ins = await q.query(
            `INSERT INTO checkpoints (agent_id, lane, seq_to, chain_root, batch_entity)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (agent_id, lane, seq_to) DO NOTHING`,
            [c.agentId, b.lane, b.seq_to, hexBuf(b.chain_root), hexBuf(b.entity_key)],
          );
          await q.query(
            `INSERT INTO batches_index (agent_id, lane, seq_from, seq_to, entity_key, arkiv_tx, chain_root, batch_root)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
            [
              c.agentId,
              b.lane,
              b.seq_from,
              b.seq_to,
              hexBuf(b.entity_key),
              b.arkiv_tx ? hexBuf(b.arkiv_tx) : null,
              hexBuf(b.chain_root),
              hexBuf(b.batch_root),
            ],
          );
          await q.query(
            `INSERT INTO agent_lanes (agent_id, lane, last_seq, last_chain_root, last_batch_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (agent_id, lane) DO UPDATE SET last_seq = excluded.last_seq,
               last_chain_root = excluded.last_chain_root, last_batch_at = excluded.last_batch_at
             WHERE agent_lanes.last_seq IS NULL OR agent_lanes.last_seq < excluded.last_seq`,
            [c.agentId, b.lane, b.seq_to, hexBuf(b.chain_root)],
          );
          return Boolean(ins.rowCount);
        });
        // P5: a duplicate (same agent, lane, seq_to) is accepted and changes nothing
        return reply
          .status(inserted ? 201 : 200)
          .send({ status: "pending" as const, duplicate: !inserted });
      },
    );

    r.post(
      "/v1/recorder/delegations",
      { ...opts, schema: { body: Delegation, response: { 200: Duplicate, 201: Duplicate } } },
      async (req, reply) => {
        const b = req.body;
        const c = ctx(req, b.lane);
        const address = hexBuf(b.session_key);
        const revocation = b.presigned_revocation
          ? await secrets.seal(c.orgId, hexBuf(b.presigned_revocation), address)
          : null;
        const ins = await inOrg(pool, c.orgId, (q) =>
          q.query(
            `INSERT INTO session_keys (agent_id, lane, address, not_before, not_after, delegation_entity, presigned_revocation_kms)
             VALUES ($1, $2, $3, to_timestamp($4), to_timestamp($5), $6, $7) ON CONFLICT DO NOTHING`,
            [
              c.agentId,
              b.lane,
              address,
              b.not_before,
              b.not_after,
              hexBuf(b.entity_key),
              revocation,
            ],
          ),
        );
        return reply.status(ins.rowCount ? 201 : 200).send({ duplicate: !ins.rowCount });
      },
    );

    r.get(
      "/v1/recorder/config",
      { ...opts, schema: { response: { 200: Config, 304: z.null() } } },
      async (req, reply) => {
        const c = ctx(req);
        const { rows } = await inOrg(pool, c.orgId, (q) =>
          q.query(
            `SELECT DISTINCT ON (lane) lane, seq_to::text, anchor_epoch::text AS epoch, anchor_tx, chain_root
               FROM checkpoints WHERE agent_id = $1 AND lane = ANY($2) AND status = 'anchored'
              ORDER BY lane, seq_to DESC`,
            [c.agentId, c.lanes],
          ),
        );
        const config = {
          readers: [] as string[], // shortcut: reader keys + grants arrive with §4.7 (P6)
          policy: null,
          approval_threshold_cents: c.approvalThresholdCents,
          privacy_level: c.privacy,
          anchored: rows.map((r) => ({
            lane: r.lane as number,
            seq_to: r.seq_to as string,
            epoch: r.epoch as string,
            anchor_tx: `0x${(r.anchor_tx as Buffer).toString("hex")}`,
            chain_root: `0x${(r.chain_root as Buffer).toString("hex")}`,
          })),
        };
        const etag = `"${sha256(jcsData(config)).toString("hex")}"`;
        reply.header("etag", etag);
        if (req.headers["if-none-match"] === etag) return reply.status(304).send(null);
        return config;
      },
    );
  });
};
