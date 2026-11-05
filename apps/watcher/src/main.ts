// Watcher service entry point (L6 §1): one process per watched chain.
//
//   node dist/main.js    env: AFR_PG_URL, AFR_WATCH_RPC_URL, ARKIV_ACCESS_KEY, AFR_IDENTITY_RPC_URL, and
//                        AFR_KMS_ENVELOPE_KEY_ID (or AFR_API_LOCAL_KEK for local dev: the API's KEK, so the
//                        watcher can open watch keys); optional AFR_WATCH_CHAIN_ID (84532),
//                        AFR_IDENTITY_CHAIN_ID (84532), AFR_WATCH_START_BLOCK
//
// shortcut: registered (eip155:) agents only; a local: agent has no registry to verify its delegations, so
// its lanes are not reconciled (logged as reconcile_failed). Its API intents still match.
import { AfrError, CHAINS } from "@afr/core";
import { createLogger } from "@afr/log";
import { kmsKeyWrapper, localKeyWrapper, OrgSecrets } from "@afr/secrets";
import { createArkivStore, MemoryWriteJournal } from "@afr/store";
import { rpcIdentityReader } from "@afr/verifier";
import { KMSClient } from "@aws-sdk/client-kms";
import pg from "pg";
import { type Chain, createPublicClient, http, type PublicClient } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";
import { runWatcher } from "./service.js";

const VIEM_CHAINS: Record<number, Chain> = {
  [CHAINS.BASE]: base,
  [CHAINS.BASE_SEPOLIA]: baseSepolia,
};

function need(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw new AfrError("CONFIG", `${name} is required`);
  return v;
}

const client = (chainId: number, url: string) =>
  createPublicClient({
    ...(VIEM_CHAINS[chainId] ? { chain: VIEM_CHAINS[chainId] } : {}),
    transport: http(url, { retryCount: 3 }),
  }) as PublicClient;

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const logger = createLogger({ name: "afr-watcher" });
  const chainId = Number(env.AFR_WATCH_CHAIN_ID ?? CHAINS.BASE_SEPOLIA);
  const identityChainId = Number(env.AFR_IDENTITY_CHAIN_ID ?? CHAINS.BASE_SEPOLIA);
  const kek = env.AFR_KMS_ENVELOPE_KEY_ID
    ? kmsKeyWrapper(new KMSClient({}), env.AFR_KMS_ENVELOPE_KEY_ID)
    : localKeyWrapper(Buffer.from(need(env, "AFR_API_LOCAL_KEK"), "hex"));
  const pool = new pg.Pool({ connectionString: need(env, "AFR_PG_URL"), max: 6 });
  const watchClient = client(chainId, need(env, "AFR_WATCH_RPC_URL"));
  if (BigInt(await watchClient.getChainId()) !== BigInt(chainId))
    throw new AfrError("CONFIG", "AFR_WATCH_RPC_URL serves another chain");
  // read-only: a throwaway writer key and a zero spend cap, so the writer queue can never send
  const store = createArkivStore({
    accessKey: need(env, "ARKIV_ACCESS_KEY"),
    writerKey: generatePrivateKey(),
    journal: new MemoryWriteJournal(),
    spendCapWei: 0n,
  });
  const stop = new AbortController();
  for (const s of ["SIGINT", "SIGTERM"] as const) process.once(s, () => stop.abort());
  try {
    await runWatcher({
      pool,
      chainId: BigInt(chainId),
      client: watchClient,
      store,
      identity: rpcIdentityReader(client(identityChainId, need(env, "AFR_IDENTITY_RPC_URL"))),
      secrets: new OrgSecrets(pool, kek),
      signal: stop.signal,
      logger,
      ...(env.AFR_WATCH_START_BLOCK ? { startBlock: BigInt(env.AFR_WATCH_START_BLOCK) } : {}),
    });
  } finally {
    await store.close();
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  // codes only: messages can carry the keyed RPC URLs
  main().catch((e) => {
    process.stderr.write(`afr-watcher: ${(e as AfrError).code ?? "ERROR"}\n`);
    process.exit(1);
  });
