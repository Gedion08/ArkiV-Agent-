// Canary entry point (P4-07): the watcher image with `node dist/canary-main.js`.
//
//   env: AFR_PG_URL, AFR_WATCH_RPC_URL, AFR_CANARY_KEY (the canary wallet's private key, 0x hex), and
//        AFR_KMS_ENVELOPE_KEY_ID (or AFR_API_LOCAL_KEK for local dev); optional AFR_WATCH_CHAIN_ID (84532),
//        AFR_CANARY_EVERY_S (3600)
import { AfrError, CHAINS } from "@afr/core";
import { createLogger } from "@afr/log";
import { kmsKeyWrapper, localKeyWrapper, OrgSecrets } from "@afr/secrets";
import { KMSClient } from "@aws-sdk/client-kms";
import pg from "pg";
import { createPublicClient, type Hex, http, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";
import { runCanary } from "./canary.js";

function need(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw new AfrError("CONFIG", `${name} is required`);
  return v;
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const logger = createLogger({ name: "afr-canary" });
  const chainId = Number(env.AFR_WATCH_CHAIN_ID ?? CHAINS.BASE_SEPOLIA);
  const key = need(env, "AFR_CANARY_KEY");
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new AfrError("CONFIG", "AFR_CANARY_KEY is invalid");
  const everyS = Number(env.AFR_CANARY_EVERY_S ?? 3600);
  if (!Number.isInteger(everyS) || everyS < 300)
    throw new AfrError("CONFIG", "AFR_CANARY_EVERY_S must be ≥ 300");
  const kek = env.AFR_KMS_ENVELOPE_KEY_ID
    ? kmsKeyWrapper(new KMSClient({}), env.AFR_KMS_ENVELOPE_KEY_ID)
    : localKeyWrapper(Buffer.from(need(env, "AFR_API_LOCAL_KEK"), "hex"));
  const client = createPublicClient({
    chain: chainId === CHAINS.BASE ? base : baseSepolia,
    transport: http(need(env, "AFR_WATCH_RPC_URL"), { retryCount: 3 }),
  }) as PublicClient;
  if ((await client.getChainId()) !== chainId)
    throw new AfrError("CONFIG", "AFR_WATCH_RPC_URL serves another chain");
  const pool = new pg.Pool({ connectionString: need(env, "AFR_PG_URL"), max: 2 });
  const stop = new AbortController();
  for (const s of ["SIGINT", "SIGTERM"] as const) process.once(s, () => stop.abort());
  try {
    await runCanary({
      pool,
      secrets: new OrgSecrets(pool, kek),
      client,
      account: privateKeyToAccount(key as Hex),
      chainId: BigInt(chainId),
      logger,
      everyMs: everyS * 1000,
      signal: stop.signal,
    });
  } finally {
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  // codes only: messages can carry the keyed RPC URL
  main().catch((e) => {
    process.stderr.write(`afr-canary: ${(e as AfrError).code ?? "ERROR"}\n`);
    process.exit(1);
  });
