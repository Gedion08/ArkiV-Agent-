// L8 apps/api v0: Fastify bootstrap. Routes: SIWE auth, orgs, agents (+ watch keys, recorder keys) and
// the recorder endpoints (§4.1–§4.4). No plaintext ever: strict schemas reject unknown fields (§1, §8).
import { randomBytes } from "node:crypto";
import { aesGcmOpen, aesGcmSeal } from "@afr/crypto";
import cookie from "@fastify/cookie";
import Fastify, { type FastifyInstance } from "fastify";
import { ZodError } from "zod";
import {
  ApiError,
  type ApiOptions,
  bufHex,
  type KeyWrapper,
  type RequireUser,
  SESSION_COOKIE,
  sha256,
} from "./http.js";
import { recorderRoutes } from "./routes/recorder.js";
import { userRoutes } from "./routes/user.js";

/** shortcut: one local AES-256-GCM master key (iv ‖ ct); per-org KMS envelopes land in P3/P6. */
export function localKeyWrapper(masterKey: Uint8Array): KeyWrapper {
  return {
    wrap: (plain, aad) => {
      const iv = randomBytes(12);
      return Buffer.concat([iv, aesGcmSeal(masterKey, iv, plain, aad)]);
    },
    unwrap: (w, aad) => aesGcmOpen(masterKey, w.subarray(0, 12), w.subarray(12), aad),
  };
}

export async function buildServer(o: ApiOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, bodyLimit: 1 << 20 });
  const now = o.now ?? Date.now;
  await app.register(cookie);

  // keep the exact bytes: the recorder HMAC covers sha256(body)
  app.addContentTypeParser("application/json", { parseAs: "buffer" }, (req, body, done) => {
    const raw = body as Buffer;
    req.rawBody = raw;
    try {
      done(null, raw.length ? JSON.parse(raw.toString("utf8")) : {});
    } catch {
      done(new ApiError(400, "INVALID_JSON"), undefined);
    }
  });

  app.setErrorHandler((e, req, reply) => {
    // never echo request content: it may be what the plaintext guard just rejected
    if (e instanceof ApiError) return reply.status(e.status).send({ code: e.code });
    if (e instanceof ZodError)
      return reply.status(400).send({
        code: "INVALID_REQUEST",
        issues: e.issues.map((i) => ({ path: i.path.join("."), code: i.code })),
      });
    const status = (e as { statusCode?: number }).statusCode;
    if (status && status < 500) return reply.status(status).send({ code: "BAD_REQUEST" });
    o.logger?.error(
      { code: (e as { code?: string }).code ?? "INTERNAL", route: req.routeOptions.url },
      "request failed",
    );
    return reply.status(500).send({ code: "INTERNAL" });
  });

  /** Session cookie + CSRF header on mutations (L8 §2). */
  const requireUser: RequireUser = async (req) => {
    const token = req.cookies[SESSION_COOKIE];
    if (!token || !/^[0-9a-f]{64}$/.test(token)) throw new ApiError(401, "UNAUTHENTICATED");
    const { rows } = await o.pool.query<{ user_id: string; wallet: Buffer; csrf_hash: Buffer }>(
      `SELECT s.user_id, u.wallet, s.csrf_hash FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > to_timestamp($2::double precision / 1000)`,
      [sha256(token), now()],
    );
    const s = rows[0];
    if (!s) throw new ApiError(401, "UNAUTHENTICATED");
    if (req.method !== "GET" && req.method !== "HEAD") {
      const csrf = req.headers["x-csrf-token"];
      if (typeof csrf !== "string" || !sha256(csrf).equals(s.csrf_hash))
        throw new ApiError(403, "CSRF");
    }
    req.user = { id: s.user_id, wallet: bufHex(s.wallet) };
  };

  await app.register(userRoutes, { ...o, now, requireUser });
  await app.register(recorderRoutes, { ...o, now });
  return app;
}
