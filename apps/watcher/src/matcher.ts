// L6 §4.2 matcher (P4-04): an observed tx from a watched key matches an intent by its tx commitment (exact)
// or, failing that, its nonce commitment (replacement: sped-up/cancelled). Unmatched txs become UNLOGGED_TX
// after the grace; an intent that turns up later (API or Arkiv batch) resolves the alert as late_intent.
//
// Pending state is the DB itself (observed_txs without a verdict), so a restart loses no timer: sweep()
// re-derives everything. Call it every 5 s and on LISTEN afr_intents / after a batch reconciliation.
//
// shortcut: grace is one value per matcher (L6 says per agent, 15–600 s); add an agents column when the
// dashboard exposes it. Watch keys are cached for the process lifetime: rotation (watch_keys.rotated_at)
// needs the cache dropped and old-key commitments tried too.
import { nonceCommit, txCommit } from "@afr/crypto";
import type { Hex } from "viem";
import type { Candidate, MatcherDb } from "./db.js";

export type MatchEvent =
  | {
      type: "UNLOGGED_TX" | "TX_REPLACED" | "LATE_INTENT";
      agentId: string;
      chainId: bigint;
      tx: Hex;
      block: bigint;
    }
  | { type: "INTENT_NOT_MINED"; agentId: string; chainId: bigint; lane: number; seq: bigint };

export interface MatcherOptions {
  chainId: bigint;
  db: MatcherDb;
  /** The agent's 32-byte watch key (sealed in watch_keys; the API's OrgSecrets opens it). */
  watchKey: (agentId: string) => Promise<Uint8Array>;
  graceMs?: number;
  /** Blocks on top of (and including) the tx's before it can alert. */
  confirmations?: number;
  /** How long an alerted tx can still be resolved by a late intent. */
  lateWindowMs?: number;
  notMinedMs?: number;
  now?: () => number;
  onEvent?: (e: MatchEvent) => void | Promise<void>;
}

export class Matcher {
  readonly o: Required<Omit<MatcherOptions, "onEvent">> & Pick<MatcherOptions, "onEvent">;
  readonly #keys = new Map<string, Uint8Array>();

  constructor(o: MatcherOptions) {
    this.o = {
      graceMs: 60_000,
      confirmations: 1,
      lateWindowMs: 3_600_000,
      notMinedMs: 3_600_000,
      now: Date.now,
      ...o,
    };
  }

  async #key(agentId: string) {
    let k = this.#keys.get(agentId);
    if (!k) {
      k = await this.o.watchKey(agentId);
      this.#keys.set(agentId, k);
    }
    return k;
  }

  /** One pass over undecided txs and stale intents; `head` is the follower's latest block. */
  async sweep(head: bigint): Promise<MatchEvent[]> {
    const { chainId, db } = this.o;
    const now = this.o.now();
    const events: MatchEvent[] = [];
    for (const c of await db.candidates(chainId, now - this.o.lateWindowMs)) {
      const e = await this.#decide(c, now, head);
      if (e) events.push(e);
    }
    for (const i of await db.notMined(chainId, now - this.o.notMinedMs))
      events.push({ type: "INTENT_NOT_MINED", chainId, ...i });
    for (const e of events) await this.o.onEvent?.(e);
    return events;
  }

  async #decide(c: Candidate, now: number, head: bigint): Promise<MatchEvent | undefined> {
    const { chainId, db } = this.o;
    const w = await this.#key(c.agentId);
    const commits = {
      tx: txCommit(w, chainId, c.tx.hash),
      nonce: nonceCommit(w, chainId, c.tx.from, c.tx.nonce),
    };
    const at = { agentId: c.agentId, chainId, tx: c.tx.hash, block: c.tx.blockNumber };
    const found = await db.findIntent(c.agentId, chainId, commits);
    if (found) {
      const kind = c.match === "unlogged" ? "late_intent" : found;
      await db.setMatch(chainId, c.tx.hash, c.agentId, kind, commits);
      if (kind === "late_intent") return { type: "LATE_INTENT", ...at };
      if (kind === "replacement") return { type: "TX_REPLACED", ...at };
      return undefined;
    }
    const confirmed = c.tx.blockNumber + BigInt(this.o.confirmations) - 1n <= head;
    if (!c.match && now >= c.seenAt + this.o.graceMs && confirmed) {
      await db.setMatch(chainId, c.tx.hash, c.agentId, "unlogged", commits);
      return { type: "UNLOGGED_TX", ...at };
    }
    return undefined;
  }
}
