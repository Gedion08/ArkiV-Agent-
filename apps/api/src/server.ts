// L8 apps/api: Fastify bootstrap. Routes: SIWE auth, orgs + members, agents (+ watch keys, recorder keys,
// watched addresses, read views) and the recorder endpoints (§4.1–§4.4). No plaintext ever: strict schemas
// reject unknown fields (§1, §8). Zod schemas validate, serialize and generate OpenAPI (§1).
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import Fastify, { type FastifyInstance } from "fastify";
import {
  hasZodFastifySchemaValidationErrors,
  isResponseSerializationError,
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
} from "fastify-type-provider-zod";
import { z } from "zod";
import {
  ApiError,
  type ApiOptions,
  bufHex,
  LIMITS,
  type RequireUser,
  SESSION_COOKIE,
  sha256,
} from "./http.js";
import { agentRoutes } from "./routes/agents.js";
import { authRoutes } from "./routes/auth.js";
import { orgRoutes } from "./routes/orgs.js";
import { recorderRoutes } from "./routes/recorder.js";
import { OrgSecrets } from "./secrets.js";

export async function buildServer(o: ApiOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, bodyLimit: 1 << 20 });
  const now = o.now ?? Date.now;
  const secrets = new OrgSecrets(o.pool, o.keys);
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  await app.register(cookie);
  await app.register(helmet); // §8 security headers
  // §8: the dashboard origin only, with cookies; without one, no CORS headers (same-origin only)
  await app.register(cors, {
    origin: o.dashboardOrigin ? [o.dashboardOrigin] : false,
    credentials: true,
  });
  await app.register(rateLimit, {
    global: true,
    ...LIMITS.session,
    // §7: counters shared by every instance; a Redis outage skips limiting rather than failing requests
    ...(o.redis ? { redis: o.redis, nameSpace: "afr-rl:", skipOnError: true } : {}),
  });
  await app.register(swagger, {
    openapi: {
      openapi: "3.1.0",
      info: { title: "AFR API", version: "1" },
    },
    transform: jsonSchemaTransform,
  });

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
    if (hasZodFastifySchemaValidationErrors(e))
      return reply.status(400).send({
        code: "INVALID_REQUEST",
        issues: e.validation.map((i) => ({ path: i.instancePath, code: i.keyword })),
      });
    const status = (e as { statusCode?: number }).statusCode;
    if (status === 429) return reply.status(429).send({ code: "RATE_LIMITED" });
    if (status && status < 500) return reply.status(status).send({ code: "BAD_REQUEST" });
    o.logger?.error(
      {
        code: isResponseSerializationError(e)
          ? "RESPONSE_SHAPE"
          : ((e as { code?: string }).code ?? "INTERNAL"),
        route: req.routeOptions.url,
      },
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

  // ALB liveness (L11 §2). No DB check: an RDS failover must not make the ALB drain every task at once.
  app.get(
    "/healthz",
    {
      config: { rateLimit: false },
      schema: { hide: true, response: { 200: z.strictObject({ status: z.literal("ok") }) } },
    },
    async () => ({ status: "ok" as const }),
  );

  const ctx = { ...o, now, requireUser, secrets };
  await app.register(authRoutes, ctx);
  await app.register(orgRoutes, ctx);
  await app.register(agentRoutes, ctx);
  await app.register(recorderRoutes, ctx);
  return app;
}
