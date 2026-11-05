// L6 §4.2 matcher (P4-04): an observed tx from a watched key matches an intent by its tx commitment (exact)
// or, failing that, its nonce commitment (replacement: sped-up/cancelled). Unmatched txs become UNLOGGED_TX
// after the grace; an intent that turns up later (API or Arkiv batch) resolves the alert as late_intent.
//
// Pending state is the DB itself (observed_txs without a verdict), so a restart loses no timer: sweep()
// re-derives everything. Call it every 5 s and on LISTEN afr_intents / after a batch reconciliation.
//
// Grace is per agent (agents.watch_grace_s, 15–600 s). Watch keys: the current one and, after a rotation,
// the previous one (intents committed before the recorder picked up the new key); the cache is dropped on
// LISTEN afr_watch_keys (forgetKeys).
import { nonceCommit, txCommit } from "@afr/crypto";
import type { Hex } from "viem";
import type { Candidate, Commits, MatcherDb } from "./db.js";

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
  /** The agent's 32-byte watch keys, current first (sealed in watch_keys; OrgSecrets opens them). */
  watchKeys: (agentId: string) => Promise<Uint8Array[]>;
  /** For candidates without their own grace. */
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
  readonly #keys = new Map<string, Uint8Array[]>();

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

  async #keysOf(agentId: string) {
    let k = this.#keys.get(agentId);
    if (!k) {
      k = await this.o.watchKeys(agentId);
      if (!k.length) throw new Error("WATCH_KEY_MISSING");
      this.#keys.set(agentId, k);
    }
    return k;
  }

  /** After a rotation: the next sweep re-reads this agent's keys (all agents without an argument). */
  forgetKeys(agentId?: string) {
    for (const [id, ks] of this.#keys)
      if (agentId === undefined || id === agentId) {
        for (const k of ks) k.fill(0);
        this.#keys.delete(id);
      }
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
    const at = { agentId: c.agentId, chainId, tx: c.tx.hash, block: c.tx.blockNumber };
    // the best match under any of the agent's keys (exact beats replacement); verdicts keep its commitments
    let found: "exact" | "replacement" | undefined;
    let commits: Commits | undefined;
    for (const w of await this.#keysOf(c.agentId)) {
      const cs = {
        tx: txCommit(w, chainId, c.tx.hash),
        nonce: nonceCommit(w, chainId, c.tx.from, c.tx.nonce),
      };
      commits ??= cs;
      const f = await db.findIntent(c.agentId, chainId, cs);
      if (f && found !== "exact") [found, commits] = [f, cs];
      if (found === "exact") break;
    }
    commits = commits as Commits;
    if (found) {
      const kind = c.match === "unlogged" ? "late_intent" : found;
      await db.setMatch(chainId, c.tx.hash, c.agentId, kind, commits);
      if (kind === "late_intent") return { type: "LATE_INTENT", ...at };
      if (kind === "replacement") return { type: "TX_REPLACED", ...at };
      return undefined;
    }
    const confirmed = c.tx.blockNumber + BigInt(this.o.confirmations) - 1n <= head;
    if (!c.match && now >= c.seenAt + (c.graceMs ?? this.o.graceMs) && confirmed) {
      await db.setMatch(chainId, c.tx.hash, c.agentId, "unlogged", commits);
      return { type: "UNLOGGED_TX", ...at };
    }
    return undefined;
  }
}
