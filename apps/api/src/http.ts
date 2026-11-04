// Shared HTTP types and helpers for apps/api (server bootstrap + route modules).
import { createHash } from "node:crypto";
import type { Logger } from "@afr/log";
import type { FastifyPluginOptions, FastifyReply, FastifyRequest } from "fastify";
import type { FastifyPluginAsyncZod } from "fastify-type-provider-zod";
import type { Redis } from "ioredis";
import type { Pool } from "pg";
import type { Client } from "viem";
import type { Q } from "./db/tenancy.js";
import type { Mailer } from "./mail.js";
import type { KeyWrapper } from "./secrets.js";

export interface ApiOptions {
  pool: Pool;
  /** SIWE (EIP-4361): the dashboard host the messages must name. */
  siweDomain: string;
  /** KEK for the per-org data keys that seal secrets at rest (§8): `kmsKeyWrapper` or `localKeyWrapper`. */
  keys: KeyWrapper;
  /** Public client for ERC-1271 / ERC-6492 wallet logins on its chain; without it only EOAs can sign in. */
  siweClient?: Client;
  /** The dashboard's origin (https://app.example): the only CORS origin (§8), and the base of invitation links. */
  dashboardOrigin?: string;
  /** Shared rate-limit counters (§7) across API instances; without it each instance counts alone (dev). */
  redis?: Redis;
  /** Invitation emails; without it the inviter passes the token on. */
  mailer?: Mailer;
  /** ms clock (tests). */
  now?: () => number;
  /** 5xx are logged by code and route only (never request content). */
  logger?: Logger;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface SessionUser {
  id: string;
  wallet: string;
}

declare module "fastify" {
  interface FastifyRequest {
    rawBody?: Buffer;
    user?: SessionUser;
  }
}

export const SESSION_COOKIE = "__Host-afr";
export const CSRF_COOKIE = "__Host-afr-csrf";
export const SESSION_TTL_MS = 12 * 3600_000;
export const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest();
export const hexBuf = (h: string) => Buffer.from(h.slice(2), "hex");
export const bufHex = (b: Buffer) => `0x${b.toString("hex")}`;

export type RequireUser = (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
export type ZodPlugin<O extends FastifyPluginOptions> = FastifyPluginAsyncZod<O>;

/** §7 rate limits. Sessions are the global default; recorder keys set theirs in routes/recorder.ts. */
export const LIMITS = {
  nonce: { max: 10, timeWindow: 60_000 }, // per IP (also the SIWE login)
  session: {
    max: 20,
    timeWindow: 1000,
    keyGenerator: (req: FastifyRequest) => {
      const t = req.cookies?.[SESSION_COOKIE];
      return t ? `s:${sha256(t).toString("hex")}` : `ip:${req.ip}`;
    },
  },
};

export const WRITE_ROLES = ["owner", "admin", "engineer"];
export const ADMIN_ROLES = ["owner", "admin"];

/** The user's role in the org (run inside `inOrg`); 404 for non-members so ids don't leak across tenants. */
export async function requireRole(q: Q, orgId: string, userId: string, allowed?: string[]) {
  const { rows } = await q.query<{ role: string }>(
    "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2",
    [orgId, userId],
  );
  const role = rows[0]?.role;
  if (!role) throw new ApiError(404, "NOT_FOUND");
  if (allowed && !allowed.includes(role)) throw new ApiError(403, "FORBIDDEN");
  return role;
}

/** §8 audit log: who, what, from which IP. */
export const audit = (
  q: Q,
  req: FastifyRequest,
  orgId: string | null,
  action: string,
  target?: string,
) =>
  q.query("INSERT INTO audit_log (org_id, actor, action, target, ip) VALUES ($1, $2, $3, $4, $5)", [
    orgId,
    req.user ? `user:${req.user.id}` : "system",
    action,
    target ?? null,
    req.ip,
  ]);
