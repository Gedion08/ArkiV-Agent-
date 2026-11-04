// Anchor service entry point (L5 §3): one leader (pg advisory lock, §3.3) ticks every 30 s (§3.2).
//
//   node dist/main.js    env: AFR_PG_URL, AFR_ANCHOR_KEY, AFR_ANCHOR_RPC_URL, ARKIV_ACCESS_KEY,
//                        AFR_ARKIV_WRITER_KEY; optional AFR_ANCHOR_CHAIN_ID (84532), AFR_ANCHOR_ARKIV_CAP_WEI
import { AfrError, ANCHOR_CONTRACTS, CHAINS } from "@afr/core";
import { createLogger, type Logger } from "@afr/log";
import { createArkivStore } from "@afr/store";
import pg from "pg";
import { createPublicClient, type Hex, http, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";
import { AnchorChain, type AnchorSigner, RECORDER_ANCHOR_ABI } from "./chain.js";
import { PgAnchorDb } from "./db.js";
import { PgWriteJournal } from "./journal.js";
import { AnchorService } from "./service.js";

/** pg advisory lock key held by the one anchor leader. */
export const LEADER_LOCK_KEY = 0xafa0c4n;
const TICK_MS = 30_000;
const CHAINS_BY_ID: Record<number, typeof base | typeof baseSepolia> = {
  [CHAINS.BASE]: base,
  [CHAINS.BASE_SEPOLIA]: baseSepolia,
};

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((r) => {
    const t = setTimeout(r, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        r();
      },
      { once: true },
    );
  });

/**
 * Waits for the leader lock, then runs `tick` every `intervalMs` until `signal` aborts. The lock lives on
 * one dedicated connection: if that drops, Postgres releases the lock, so we throw and let the process restart.
 */
export async function runAsLeader(o: {
  pool: pg.Pool;
  tick: () => Promise<unknown>;
  signal: AbortSignal;
  intervalMs?: number;
  retryLockMs?: number;
  logger?: Logger;
}): Promise<void> {
  const { pool, signal, intervalMs = TICK_MS, retryLockMs = 10_000 } = o;
  const c = await pool.connect();
  let lost = false;
  c.on("error", () => {
    lost = true;
  });
  let held = false;
  try {
    while (!signal.aborted && !held) {
      const { rows } = await c.query("SELECT pg_try_advisory_lock($1) AS ok", [
        LEADER_LOCK_KEY.toString(),
      ]);
      held = rows[0].ok as boolean;
      if (!held) await sleep(retryLockMs, signal);
    }
    if (!held) return;
    o.logger?.info({ event: "leader" }, "anchor leader lock held");
    while (!signal.aborted && !lost) {
      // a failed tick is retried next time: its state is in the DB and every step resumes from there
      await o.tick().catch((e) => o.logger?.error({ code: (e as AfrError).code ?? "TICK_FAILED" }));
      await sleep(intervalMs, signal);
    }
    if (lost) throw new AfrError("LEADER_LOST", "leader connection dropped");
  } finally {
    if (held && !lost)
      await c.query("SELECT pg_advisory_unlock($1)", [LEADER_LOCK_KEY.toString()]).catch(() => {});
    c.release(lost);
  }
}

function need(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw new AfrError("CONFIG", `${name} is required`);
  return v;
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const logger = createLogger({ name: "afr-anchor" });
  const chainId = Number(env.AFR_ANCHOR_CHAIN_ID ?? CHAINS.BASE_SEPOLIA);
  const chain = CHAINS_BY_ID[chainId];
  const contract = ANCHOR_CONTRACTS[chainId]?.at(-1)?.address;
  if (!chain || !contract) throw new AfrError("CONFIG", `no RecorderAnchor on chain ${chainId}`);
  // shortcut: a local key; the KMS account (L5 §3.3) replaces it in P3-12
  const signer = privateKeyToAccount(need(env, "AFR_ANCHOR_KEY") as Hex) as AnchorSigner;
  const publicClient = createPublicClient({
    chain,
    transport: http(need(env, "AFR_ANCHOR_RPC_URL"), { retryCount: 3 }),
  }) as PublicClient;
  const allowed = await publicClient.readContract({
    address: contract,
    abi: RECORDER_ANCHOR_ABI,
    functionName: "isRecorder",
    args: [signer.address],
  });
  if (!allowed)
    throw new AfrError("NOT_RECORDER", "the anchor key is not on the recorder allowlist");

  const pool = new pg.Pool({ connectionString: need(env, "AFR_PG_URL"), max: 4 });
  const store = createArkivStore({
    accessKey: need(env, "ARKIV_ACCESS_KEY"),
    writerKey: need(env, "AFR_ARKIV_WRITER_KEY"),
    journal: new PgWriteJournal(pool),
    spendCapWei: BigInt(env.AFR_ANCHOR_ARKIV_CAP_WEI ?? "100000000000000000"), // 0.1 GLM
  });
  const service = new AnchorService({
    db: new PgAnchorDb(pool),
    store,
    chain: new AnchorChain({ publicClient, chain, contract, signer }),
    logger,
  });
  const stop = new AbortController();
  for (const s of ["SIGINT", "SIGTERM"] as const) process.once(s, () => stop.abort());
  try {
    await runAsLeader({ pool, tick: () => service.tick(), signal: stop.signal, logger });
  } finally {
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  // codes only: messages can carry the keyed RPC URL
  main().catch((e) => {
    process.stderr.write(`afr-anchor: ${(e as AfrError).code ?? "ERROR"}\n`);
    process.exit(1);
  });
