// L2 §10 outbox → API. Notices are journaled with the state change that implies them and delivered at
// least once; the API dedupes by (kind, agent, lane, seq). Heartbeats are best effort, never queued.
import { signRecorderRequest } from "@afr/crypto";
import type { Logger } from "@afr/log";
import type { Journal, NoticeKind, NoticeRow } from "./journal.js";

const PATHS: Record<NoticeKind | "heartbeat", string> = {
  checkpoint: "/v1/recorder/checkpoints",
  delegation: "/v1/recorder/delegations",
  tx_intent: "/v1/recorder/intents",
  heartbeat: "/v1/recorder/heartbeat",
};
/** L2 §10: retries with exponential backoff for up to 7 days. */
export const OUTBOX_MAX_AGE_MS = 7 * 86_400_000;
const BACKOFF_MAX_MS = 3_600_000;
const INTENTS_PER_CALL = 100; // L8 §7

export interface OutboxOptions {
  journal: Journal;
  /** API origin, e.g. https://api.afr.example (paths are absolute under it). */
  url: string;
  /** afr_rk_<id>_<secret> */
  token: string;
  now: () => number;
  fetch?: typeof fetch;
  logger?: Logger;
}

type Outcome = "ok" | "rejected" | "retry";
type Group = { kind: NoticeKind; rows: NoticeRow[]; body: unknown };

export class Outbox {
  readonly #o: OutboxOptions;
  readonly #fetch: typeof fetch;
  #draining: Promise<number> | undefined;

  constructor(o: OutboxOptions) {
    this.#o = o;
    this.#fetch = o.fetch ?? fetch;
  }

  async #post(kind: NoticeKind | "heartbeat", body: unknown): Promise<Outcome> {
    const url = new URL(`${this.#o.url.replace(/\/$/, "")}${PATHS[kind]}`);
    const json = JSON.stringify(body);
    const headers = signRecorderRequest(
      this.#o.token,
      "POST",
      url.pathname + url.search,
      json,
      Math.floor(this.#o.now() / 1000),
    );
    try {
      const res = await this.#fetch(url, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
        body: json,
      });
      if (res.ok) return "ok";
      // a 4xx won't fix itself on retry (bad payload, revoked key), except timeouts and rate limits
      if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) {
        this.#o.logger?.warn(
          { code: "OUTBOX_REJECTED", kind, status: res.status },
          "notice rejected",
        );
        return "rejected";
      }
      return "retry";
    } catch {
      return "retry"; // network error: the API is unreachable
    }
  }

  /** Delivers due notices until none are due or the API stops answering; returns the number sent. */
  drain(): Promise<number> {
    this.#draining ??= this.#drain().finally(() => {
      this.#draining = undefined;
    });
    return this.#draining;
  }

  async #drain(): Promise<number> {
    const { journal } = this.#o;
    let sent = 0;
    for (;;) {
      const now = this.#o.now();
      const rows = journal.dueNotices(now, INTENTS_PER_CALL);
      if (!rows.length) return sent;
      const expired = rows.filter((r) => now - r.createdAt > OUTBOX_MAX_AGE_MS);
      if (expired.length) {
        journal.deleteNotices(expired.map((r) => r.id));
        this.#o.logger?.warn({ code: "OUTBOX_EXPIRED", count: expired.length }, "notices dropped");
      }
      const live = rows.filter((r) => !expired.includes(r));
      const intents = live.filter((r) => r.kind === "tx_intent");
      const groups: Group[] = [
        ...(intents.length
          ? [
              {
                kind: "tx_intent" as const,
                rows: intents,
                body: { items: intents.map((r) => r.payload) },
              },
            ]
          : []),
        ...live
          .filter((r) => r.kind !== "tx_intent")
          .map((r) => ({ kind: r.kind, rows: [r], body: r.payload })),
      ];
      for (const g of groups) {
        const outcome = await this.#post(g.kind, g.body);
        const ids = g.rows.map((r) => r.id);
        if (outcome === "retry") {
          const attempts = Math.max(...g.rows.map((r) => r.attempts));
          journal.retryNotices(ids, now + Math.min(1000 * 2 ** attempts, BACKOFF_MAX_MS));
          return sent; // the API is down or overloaded: wait out the backoff
        }
        journal.deleteNotices(ids);
        if (outcome === "ok") sent += ids.length;
      }
    }
  }

  /** Best effort; a missed heartbeat only shows as a later `last_heartbeat_at`. */
  async heartbeat(payload: Record<string, unknown>): Promise<boolean> {
    return (await this.#post("heartbeat", payload)) === "ok";
  }
}
