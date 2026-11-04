// L3 §9 mirror mode: every entity the primary store (Arkiv) confirmed is written to the mirror
// (Postgres) too. It's the dashboard's read fallback and the source for re-creating entities after an
// Arkiv rollback. Requests are journaled when the primary confirms, so a crash loses none; delivery is
// fail-open (the primary path never waits) and idempotent (same idempotency key, same entity).
import { AfrError } from "@afr/core";
import type { Logger } from "@afr/log";
import type { EvidenceStore } from "@afr/store";
import type { Journal } from "./journal.js";
import { putOnce } from "./statements.js";

const BACKOFF_MAX_MS = 3_600_000;
const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

export interface MirrorOptions {
  journal: Journal;
  store: EvidenceStore;
  now: () => number;
  logger?: Logger;
}

export class Mirror {
  readonly #o: MirrorOptions;
  #draining: Promise<number> | undefined;
  /** After a failure the whole mirror waits out the backoff, not just that row. */
  #pausedUntil = 0;

  constructor(o: MirrorOptions) {
    this.#o = o;
  }

  /** Copies due entities in order until none are due or the mirror fails; returns the number copied. */
  drain(): Promise<number> {
    this.#draining ??= this.#drain().finally(() => {
      this.#draining = undefined;
    });
    return this.#draining;
  }

  async #drain(): Promise<number> {
    const { journal, store } = this.#o;
    let copied = 0;
    for (;;) {
      const now = this.#o.now();
      if (now < this.#pausedUntil) return copied;
      const rows = journal.dueMirrors(now);
      if (!rows.length) return copied;
      for (const r of rows) {
        try {
          const key = await putOnce(store, r.req);
          // an id the mirror already held must carry our bytes (a reused or diverged mirror DB)
          const got = key ? await store.get(key, r.req.schema) : null;
          if (!got || !sameBytes(got.payload, r.req.payload))
            throw new AfrError("MIRROR_MISMATCH", "mirror entity differs from the primary's");
          journal.deleteMirror(r.id);
          copied++;
        } catch (e) {
          // kept until it lands (it's the rollback source); the mirror being down never blocks the primary
          this.#pausedUntil = now + Math.min(1000 * 2 ** r.attempts, BACKOFF_MAX_MS);
          journal.retryMirror(r.id, this.#pausedUntil);
          if (r.attempts === 0)
            this.#o.logger?.warn(
              { code: (e as { code?: string }).code ?? "MIRROR_ERROR", schema: r.req.schema },
              "mirror write failed",
            );
          return copied;
        }
      }
    }
  }
}
