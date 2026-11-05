// Synthetic canary (P4-07; L6 W9, L11 §5, ARCHITECTURE §13). Every hour a dedicated wallet sends two 0-value
// self-transfers on the watched chain: one logged (its intent goes to tx_intents before the broadcast, as the
// recorder's does) and one unlogged. The round passes when exactly one UNLOGGED_TX opens, for the unlogged tx,
// and the logged one matches; the canary then acks its own alerts. The result is logged as canary_ok /
// canary_failed, which CloudWatch alarms on.
// shortcut: the intent goes straight into tx_intents (the watcher's DB role), not through POST
// /v1/recorder/intents, so the API's intake isn't covered; upgrade once the canary holds a recorder key.
import { randomBytes } from "node:crypto";
import { type AfrError, agentKey } from "@afr/core";
import { nonceCommit, txCommit } from "@afr/crypto";
import type { Logger } from "@afr/log";
import type { OrgSecrets } from "@afr/secrets";
import type { Pool } from "pg";
import { type Hex, keccak256, type PublicClient, type TransactionSerializableEIP1559 } from "viem";
import { pgWatchKeys } from "./service.js";

/** One canary agent per watched chain: a fixed local: id (no ERC-8004 identity, so no lanes to audit). */
export const canaryAgentId = (chainId: bigint) =>
  `local:afc0a2a1-0000-4000-8000-${chainId.toString().padStart(12, "0")}`;
const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");

export interface CanaryOptions {
  pool: Pool;
  secrets: OrgSecrets;
  client: PublicClient;
  /** A viem local account; narrowed, as its full generic type overflows tsc's stack in larger programs. */
  account: { address: Hex; signTransaction(tx: TransactionSerializableEIP1559): Promise<Hex> };
  chainId: bigint;
  logger?: Logger;
  /** How long to wait for the alert after inclusion (default 5 min). */
  alertTimeoutMs?: number;
  pollMs?: number;
  /** Below this the round doesn't send (default 0.0005 ETH). */
  minBalanceWei?: bigint;
}

export interface CanaryResult {
  ok: boolean;
  /** Why the round failed. */
  code?: string;
  logged?: Hex;
  unlogged?: Hex;
  /** Unlogged tx inclusion → alert first seen. */
  latencyMs?: number;
}

/** Creates the canary org, agent (15 s grace), watch key and watched address once; returns agents.id. */
export async function provisionCanary(o: CanaryOptions): Promise<string> {
  const id = canaryAgentId(o.chainId);
  const found = await o.pool.query<{ id: string }>("SELECT id FROM agents WHERE agent_id = $1", [
    id,
  ]);
  if (found.rows[0]) return found.rows[0].id;
  const org =
    (await o.pool.query<{ id: string }>("SELECT id FROM orgs WHERE name = 'afr-canary' LIMIT 1"))
      .rows[0]?.id ??
    (
      await o.pool.query<{ id: string }>(
        "INSERT INTO orgs (name) VALUES ('afr-canary') RETURNING id",
      )
    ).rows[0]?.id;
  const ak = buf(agentKey(id));
  const wk = randomBytes(32);
  const sealed = await o.secrets.seal(org as string, wk, ak);
  wk.fill(0);
  const c = await o.pool.connect();
  try {
    await c.query("BEGIN");
    const agent = (
      await c.query<{ id: string }>(
        `INSERT INTO agents (org_id, agent_id, agent_key, name, watch_grace_s) VALUES ($1, $2, $3, 'canary', 15)
         RETURNING id`,
        [org, id, ak],
      )
    ).rows[0]?.id as string;
    await c.query("INSERT INTO watch_keys (agent_id, kms_ciphertext) VALUES ($1, $2)", [
      agent,
      sealed,
    ]);
    await c.query(
      `INSERT INTO watched_addresses (org_id, agent_id, chain_id, address, kind, source)
       VALUES ($1, $2, $3, $4, 'eoa', 'canary')`,
      [org, agent, o.chainId.toString(), buf(o.account.address.toLowerCase() as Hex)],
    );
    await c.query("COMMIT");
    return agent;
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One round. Never resends: a failed or uncertain broadcast fails the round, and the next starts fresh. */
export async function canaryRound(o: CanaryOptions, agentId: string): Promise<CanaryResult> {
  const { client, account, chainId, pool } = o;
  const from = account.address;
  const started = new Date();
  if ((await client.getBalance({ address: from })) < (o.minBalanceWei ?? 500_000_000_000_000n))
    return { ok: false, code: "LOW_BALANCE" };
  const [wk] = await pgWatchKeys(pool, o.secrets)(agentId);
  if (!wk) return { ok: false, code: "NO_WATCH_KEY" };
  const fees = await client.estimateFeesPerGas();
  const nonce = BigInt(await client.getTransactionCount({ address: from, blockTag: "pending" }));
  const sign = (n: bigint) =>
    account.signTransaction({
      chainId: Number(chainId),
      type: "eip1559",
      to: from,
      value: 0n,
      nonce: Number(n),
      gas: 21_000n,
      maxFeePerGas: fees.maxFeePerGas,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    });
  const loggedRaw = await sign(nonce);
  const unloggedRaw = await sign(nonce + 1n);
  const logged = keccak256(loggedRaw);
  const unlogged = keccak256(unloggedRaw);
  try {
    // the logged one: intent first, as the recorder's outbox does before the SDK broadcasts
    await pool.query(
      `INSERT INTO tx_intents (agent_id, lane, seq, chain_id, tx_commit, nonce_commit) VALUES ($1, 0, $2, $3, $4, $5)`,
      [
        agentId,
        Date.now().toString(),
        chainId.toString(),
        buf(txCommit(wk, chainId, logged)),
        buf(nonceCommit(wk, chainId, from, nonce)),
      ],
    );
    await pool.query("SELECT pg_notify('afr_intents', $1)", [agentId]);
  } finally {
    wk.fill(0);
  }
  try {
    await client.sendRawTransaction({ serializedTransaction: loggedRaw });
    await client.sendRawTransaction({ serializedTransaction: unloggedRaw });
  } catch {
    return { ok: false, code: "SEND_FAILED", logged, unlogged };
  }
  let included: number;
  try {
    await client.waitForTransactionReceipt({ hash: logged, timeout: 120_000 });
    const r = await client.waitForTransactionReceipt({ hash: unlogged, timeout: 120_000 });
    included = Number((await client.getBlock({ blockNumber: r.blockNumber })).timestamp) * 1000;
  } catch {
    return { ok: false, code: "NOT_INCLUDED", logged, unlogged };
  }

  const key = `UNLOGGED_TX:${chainId}:${unlogged}`;
  const deadline = Date.now() + (o.alertTimeoutMs ?? 300_000);
  let alerts: { dedupe_key: string; first_seen_at: Date }[] = [];
  let matched: string | undefined;
  while (Date.now() < deadline) {
    alerts = (
      await pool.query(
        `SELECT dedupe_key, first_seen_at FROM alerts
          WHERE agent_id = $1 AND type = 'UNLOGGED_TX' AND last_seen_at >= $2`,
        [agentId, started],
      )
    ).rows;
    matched = (
      await pool.query<{ kind: string }>(
        "SELECT kind FROM tx_matches WHERE chain_id = $1 AND tx_hash = $2 AND agent_id = $3",
        [chainId.toString(), buf(logged), agentId],
      )
    ).rows[0]?.kind;
    if (alerts.some((a) => a.dedupe_key === key) && matched) break;
    await sleep(o.pollMs ?? 5_000);
  }
  // let a stray second alert (the logged tx) surface before judging "exactly one"
  if (alerts.length === 1) await sleep(o.pollMs ?? 5_000);
  alerts = (
    await pool.query(
      `SELECT dedupe_key, first_seen_at FROM alerts
        WHERE agent_id = $1 AND type = 'UNLOGGED_TX' AND last_seen_at >= $2`,
      [agentId, started],
    )
  ).rows;
  await ackCanaryAlerts(pool, agentId);
  const mine = alerts.find((a) => a.dedupe_key === key);
  const code = !mine
    ? "NO_ALERT"
    : alerts.length > 1
      ? "EXTRA_ALERT"
      : matched !== "exact"
        ? "LOGGED_NOT_MATCHED"
        : undefined;
  return {
    ok: !code,
    ...(code ? { code } : {}),
    logged,
    unlogged,
    ...(mine ? { latencyMs: Math.max(0, mine.first_seen_at.getTime() - included) } : {}),
  };
}

/** W9 "auto-acked": every open alert of the canary agent (INTENT_NOT_MINED leftovers too). */
async function ackCanaryAlerts(pool: Pool, agentId: string) {
  await pool.query(
    `WITH a AS (UPDATE alerts SET status = 'acked' WHERE agent_id = $1 AND status = 'open' RETURNING id, org_id)
     INSERT INTO alert_events (org_id, alert_id, kind, actor) SELECT org_id, id, 'acked', 'canary' FROM a`,
    [agentId],
  );
}

/** Provisions, then runs a round every `everyMs` until aborted. */
export async function runCanary(
  o: CanaryOptions & { everyMs?: number; signal: AbortSignal },
): Promise<void> {
  const agentId = await provisionCanary(o);
  o.logger?.info({ event: "canary_ready", address: o.account.address.toLowerCase() });
  while (!o.signal.aborted) {
    const t0 = Date.now();
    let r: CanaryResult;
    try {
      r = await canaryRound(o, agentId);
    } catch (e) {
      r = { ok: false, code: (e as AfrError).code ?? "ERROR" };
    }
    const fields = {
      ...(r.code ? { code: r.code } : {}),
      ...(r.logged ? { logged: r.logged, unlogged: r.unlogged } : {}),
      ...(r.latencyMs !== undefined ? { latency_ms: r.latencyMs } : {}),
    };
    if (r.ok) o.logger?.info({ event: "canary_ok", ...fields });
    else o.logger?.error({ event: "canary_failed", ...fields });
    const wait = Math.max(0, (o.everyMs ?? 3_600_000) - (Date.now() - t0));
    await new Promise<void>((res) => {
      const t = setTimeout(res, wait);
      o.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(t);
          res();
        },
        { once: true },
      );
    });
  }
}
