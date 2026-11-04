// API entry point (L8, L11 §2): migrate (advisory-locked, so concurrent task starts are safe), then serve.
//
//   node dist/main.js   env: AFR_PG_URL, AFR_SIWE_DOMAIN, and AFR_KMS_ENVELOPE_KEY_ID (or AFR_API_LOCAL_KEK,
//                       32-byte hex, for local dev); optional AFR_DASHBOARD_ORIGIN, AFR_REDIS_URL,
//                       AFR_SMTP_URL + AFR_MAIL_FROM, AFR_SIWE_RPC_URL + AFR_SIWE_CHAIN_ID (8453), PORT (8080), HOST

import { AfrError } from "@afr/core";
import { createLogger } from "@afr/log";
import { KMSClient } from "@aws-sdk/client-kms";
import type { FastifyInstance } from "fastify";
import { Redis } from "ioredis";
import pg from "pg";
import { type Client, createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import { migrate } from "./db/migrations.js";
import type { ApiOptions } from "./http.js";
import { smtpMailer } from "./mail.js";
import { kmsKeyWrapper, localKeyWrapper } from "./secrets.js";
import { buildServer } from "./server.js";

const SIWE_CHAINS = { [base.id]: base, [baseSepolia.id]: baseSepolia } as const;

const config = (msg: string) => new AfrError("CONFIG", msg);
function need(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw config(`${name} is required`);
  return v;
}

/** Everything main needs from env, checked before any connection is opened. */
export function readApiEnv(env: NodeJS.ProcessEnv) {
  const pgUrl = need(env, "AFR_PG_URL");
  const siweDomain = need(env, "AFR_SIWE_DOMAIN");
  const kmsKey = env.AFR_KMS_ENVELOPE_KEY_ID;
  const localKek = env.AFR_API_LOCAL_KEK;
  if (!kmsKey && !localKek)
    throw config("AFR_KMS_ENVELOPE_KEY_ID or AFR_API_LOCAL_KEK is required");
  if (!kmsKey && !/^[0-9a-f]{64}$/.test(localKek ?? ""))
    throw config("AFR_API_LOCAL_KEK must be 32 bytes of lowercase hex");
  const origin = env.AFR_DASHBOARD_ORIGIN;
  if (origin && !/^(https:\/\/[^/\s]+|http:\/\/(localhost|127\.0\.0\.1)(:\d+)?)$/.test(origin))
    throw config("AFR_DASHBOARD_ORIGIN must be an https origin (or http://localhost)");
  if (!env.AFR_SMTP_URL !== !env.AFR_MAIL_FROM)
    throw config("AFR_SMTP_URL and AFR_MAIL_FROM go together");
  const siweChainId = Number(env.AFR_SIWE_CHAIN_ID ?? base.id);
  const siweChain = SIWE_CHAINS[siweChainId as keyof typeof SIWE_CHAINS];
  if (env.AFR_SIWE_RPC_URL && !siweChain) throw config("AFR_SIWE_CHAIN_ID must be 8453 or 84532");
  const port = Number(env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw config("PORT is invalid");
  return {
    pgUrl,
    siweDomain,
    kmsKey,
    localKek,
    origin,
    redisUrl: env.AFR_REDIS_URL,
    smtp: env.AFR_SMTP_URL
      ? { url: env.AFR_SMTP_URL, from: env.AFR_MAIL_FROM as string }
      : undefined,
    siweRpc: env.AFR_SIWE_RPC_URL ? { url: env.AFR_SIWE_RPC_URL, chain: siweChain } : undefined,
    port,
    host: env.HOST ?? "0.0.0.0",
  };
}

/** Migrates, listens, and returns a close() that drains requests, then the pool and Redis. */
export async function startApi(
  env: NodeJS.ProcessEnv,
): Promise<{ app: FastifyInstance; url: string; close: () => Promise<void> }> {
  const c = readApiEnv(env);
  const logger = createLogger({ name: "afr-api" });
  const pool = new pg.Pool({ connectionString: c.pgUrl, max: 10 });
  const redis = c.redisUrl ? new Redis(c.redisUrl) : undefined;
  try {
    await migrate(pool);
    const o: ApiOptions = {
      pool,
      siweDomain: c.siweDomain,
      keys: c.kmsKey
        ? kmsKeyWrapper(new KMSClient({}), c.kmsKey)
        : localKeyWrapper(Buffer.from(c.localKek as string, "hex")),
      logger,
      ...(c.origin ? { dashboardOrigin: c.origin } : {}),
      ...(redis ? { redis } : {}),
      ...(c.smtp ? { mailer: smtpMailer(c.smtp.url, c.smtp.from) } : {}),
      ...(c.siweRpc
        ? {
            siweClient: createPublicClient({
              chain: c.siweRpc.chain,
              transport: http(c.siweRpc.url, { retryCount: 2 }),
            }) as Client,
          }
        : {}),
    };
    const app = await buildServer(o);
    const url = await app.listen({ port: c.port, host: c.host });
    logger.info({ event: "listening", port: (app.server.address() as { port: number }).port });
    return {
      app,
      url,
      close: async () => {
        await app.close();
        await pool.end();
        redis?.disconnect();
      },
    };
  } catch (e) {
    await pool.end().catch(() => {});
    redis?.disconnect();
    throw e;
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  startApi(process.env).then(
    (api) => {
      for (const s of ["SIGINT", "SIGTERM"] as const)
        process.once(s, () => {
          api.close().then(
            () => process.exit(0),
            () => process.exit(1),
          );
        });
    },
    // codes only: messages can carry the PG or Redis URL
    (e) => {
      process.stderr.write(`afr-api: ${(e as AfrError).code ?? "ERROR"}\n`);
      process.exit(1);
    },
  );
