// L8 §4.2 orgs, members, invitations. Members and roles: owner/admin; only an owner grants or removes
// `owner`, and an org always keeps one.
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { inOrg, inTx, type Q } from "../db/tenancy.js";
import {
  ADMIN_ROLES,
  ApiError,
  type ApiOptions,
  audit,
  bufHex,
  hexBuf,
  type RequireUser,
  requireRole,
  sha256,
  type ZodPlugin,
} from "../http.js";
import { Addr, AddrOut, Ok, OrgParam, Role } from "../schemas.js";

const INVITE_TTL_MS = 7 * 86_400_000;
const INVITE_RE = /^afr_inv_[0-9a-f]{64}$/;

const Org = z.strictObject({ id: z.uuid(), name: z.string(), plan: z.string(), role: Role });
const OrgDetail = Org.extend({ region: z.string() });
const Member = z.strictObject({ user_id: z.uuid(), wallet: AddrOut, role: Role });
const Name = z.string().min(1).max(200);

export const orgRoutes: ZodPlugin<
  ApiOptions & { now: () => number; requireUser: RequireUser }
> = async (app, o) => {
  const { pool, now } = o;
  const auth = { preHandler: o.requireUser };
  const uid = (req: { user?: { id: string } }) => (req.user as { id: string }).id;

  /** Locks the org's owners, so two concurrent demotions can't remove the last one. */
  const ownerCount = async (q: Q, orgId: string) =>
    (
      await q.query(
        "SELECT user_id FROM memberships WHERE org_id = $1 AND role = 'owner' FOR UPDATE",
        [orgId],
      )
    ).rowCount ?? 0;

  app.get(
    "/v1/orgs",
    { ...auth, schema: { response: { 200: z.strictObject({ orgs: z.array(Org) }) } } },
    async (req) => {
      // system query: a user's own memberships span orgs
      const { rows } = await pool.query(
        `SELECT o.id, o.name, o.plan, m.role FROM orgs o JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1 ORDER BY o.created_at`,
        [uid(req)],
      );
      return { orgs: rows };
    },
  );

  app.post(
    "/v1/orgs",
    {
      ...auth,
      schema: { body: z.strictObject({ name: Name }), response: { 201: Org.omit({ plan: true }) } },
    },
    async (req, reply) => {
      // system tx: the org doesn't exist yet, so there's no tenant to scope to
      const id = await inTx(pool, async (q) => {
        const { rows } = await q.query<{ id: string }>(
          "INSERT INTO orgs (name) VALUES ($1) RETURNING id",
          [req.body.name],
        );
        const org = rows[0]?.id as string;
        await q.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')", [
          org,
          uid(req),
        ]);
        await audit(q, req, org, "org.create", org);
        return org;
      });
      return reply.status(201).send({ id, name: req.body.name, role: "owner" as const });
    },
  );

  app.get(
    "/v1/orgs/:org",
    { ...auth, schema: { params: OrgParam, response: { 200: OrgDetail } } },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        const role = await requireRole(q, req.params.org, uid(req));
        const { rows } = await q.query("SELECT id, name, plan, region FROM orgs WHERE id = $1", [
          req.params.org,
        ]);
        return { ...rows[0], role };
      }),
  );

  app.patch(
    "/v1/orgs/:org",
    {
      ...auth,
      schema: { params: OrgParam, body: z.strictObject({ name: Name }), response: { 200: Ok } },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        await requireRole(q, req.params.org, uid(req), ADMIN_ROLES);
        await q.query("UPDATE orgs SET name = $2 WHERE id = $1", [req.params.org, req.body.name]);
        await audit(q, req, req.params.org, "org.update", req.params.org);
        return { ok: true as const };
      }),
  );

  // ── members ──
  app.get(
    "/v1/orgs/:org/members",
    {
      ...auth,
      schema: { params: OrgParam, response: { 200: z.strictObject({ members: z.array(Member) }) } },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        await requireRole(q, req.params.org, uid(req));
        const { rows } = await q.query<{ user_id: string; wallet: Buffer; role: string }>(
          `SELECT m.user_id, u.wallet, m.role FROM memberships m JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 ORDER BY m.role, u.wallet`,
          [req.params.org],
        );
        return {
          members: rows.map((r) => ({ ...r, wallet: bufHex(r.wallet) })) as z.infer<
            typeof Member
          >[],
        };
      }),
  );

  /** Adds a wallet as a member, or changes an existing member's role. */
  app.post(
    "/v1/orgs/:org/members",
    {
      ...auth,
      schema: {
        params: OrgParam,
        body: z.strictObject({ wallet: Addr, role: Role }),
        response: { 200: Member },
      },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        const org = req.params.org;
        const mine = await requireRole(q, org, uid(req), ADMIN_ROLES);
        const { wallet, role } = req.body;
        const { rows } = await q.query<{ id: string }>(
          "INSERT INTO users (wallet) VALUES ($1) ON CONFLICT (wallet) DO UPDATE SET wallet = excluded.wallet RETURNING id",
          [hexBuf(wallet)],
        );
        const userId = rows[0]?.id as string;
        const prev = (
          await q.query<{ role: string }>(
            "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
            [org, userId],
          )
        ).rows[0]?.role;
        if ((role === "owner" || prev === "owner") && mine !== "owner")
          throw new ApiError(403, "FORBIDDEN");
        if (prev === "owner" && role !== "owner" && (await ownerCount(q, org)) <= 1)
          throw new ApiError(409, "LAST_OWNER");
        await q.query(
          `INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3)
           ON CONFLICT (org_id, user_id) DO UPDATE SET role = excluded.role`,
          [org, userId, role],
        );
        await audit(q, req, org, prev ? "member.role" : "member.add", userId);
        return { user_id: userId, wallet, role };
      }),
  );

  app.delete(
    "/v1/orgs/:org/members/:userId",
    {
      ...auth,
      schema: {
        params: OrgParam.extend({ userId: z.uuid() }),
        response: { 200: Ok },
      },
    },
    async (req) =>
      inOrg(pool, req.params.org, async (q) => {
        const { org, userId } = req.params;
        const self = userId === uid(req);
        const mine = await requireRole(q, org, uid(req), self ? undefined : ADMIN_ROLES);
        const target = (
          await q.query<{ role: string }>(
            "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
            [org, userId],
          )
        ).rows[0]?.role;
        if (!target) throw new ApiError(404, "NOT_FOUND");
        if (target === "owner") {
          if (mine !== "owner") throw new ApiError(403, "FORBIDDEN");
          if ((await ownerCount(q, org)) <= 1) throw new ApiError(409, "LAST_OWNER");
        }
        await q.query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2", [org, userId]);
        await audit(q, req, org, "member.remove", userId);
        return { ok: true as const };
      }),
  );

  // ── invitations ──
  app.post(
    "/v1/orgs/:org/invitations",
    {
      ...auth,
      schema: {
        params: OrgParam,
        body: z.strictObject({
          role: Role,
          // binds the invitation to one wallet; without it any signed-in wallet holding the token may accept
          wallet: Addr.optional(),
          email: z.email().max(320).optional(),
        }),
        response: {
          201: z.strictObject({ id: z.uuid(), token: z.string(), expires_at: z.string() }),
        },
      },
    },
    async (req, reply) => {
      const token = `afr_inv_${randomBytes(32).toString("hex")}`;
      const expires = new Date(now() + INVITE_TTL_MS);
      const id = await inOrg(pool, req.params.org, async (q) => {
        const org = req.params.org;
        const mine = await requireRole(q, org, uid(req), ADMIN_ROLES);
        if (req.body.role === "owner" && mine !== "owner") throw new ApiError(403, "FORBIDDEN");
        const { rows } = await q.query<{ id: string }>(
          `INSERT INTO invitations (org_id, role, wallet, email, token_hash, created_by, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
          [
            org,
            req.body.role,
            req.body.wallet ? hexBuf(req.body.wallet) : null,
            req.body.email ?? null,
            sha256(token),
            uid(req),
            expires,
          ],
        );
        const id = rows[0]?.id as string;
        await audit(q, req, org, "invitation.create", id);
        return id;
      });
      // shortcut: the token is returned to the inviter to pass on; email delivery comes with the notifier (§5)
      return reply.status(201).send({ id, token, expires_at: expires.toISOString() });
    },
  );

  app.post(
    "/v1/invitations/accept",
    {
      ...auth,
      schema: {
        body: z.strictObject({ token: z.string().regex(INVITE_RE) }),
        response: { 200: z.strictObject({ org_id: z.uuid(), role: Role }) },
      },
    },
    async (req) =>
      // system tx: the token, not a membership, says which org this is
      inTx(pool, async (q) => {
        const { rows } = await q.query<{
          id: string;
          org_id: string;
          role: string;
          wallet: Buffer | null;
        }>(
          `SELECT id, org_id, role, wallet FROM invitations WHERE token_hash = $1
           AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2 FOR UPDATE`,
          [sha256(req.body.token), new Date(now())],
        );
        const inv = rows[0];
        const me = req.user as { id: string; wallet: string };
        if (!inv || (inv.wallet && bufHex(inv.wallet) !== me.wallet))
          throw new ApiError(404, "INVITATION_INVALID");
        await q.query(
          "UPDATE invitations SET accepted_at = now(), accepted_by = $2 WHERE id = $1",
          [inv.id, me.id],
        );
        // an existing member keeps their role; the invitation is still used up
        await q.query(
          "INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
          [inv.org_id, me.id, inv.role],
        );
        await audit(q, req, inv.org_id, "invitation.accept", inv.id);
        const role = (
          await q.query<{ role: string }>(
            "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
            [inv.org_id, me.id],
          )
        ).rows[0]?.role;
        return { org_id: inv.org_id, role: role as z.infer<typeof Role> };
      }),
  );
};
