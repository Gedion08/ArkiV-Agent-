// Durable WriterQueue journal for the anchor service's Arkiv writes (L3 §7), in `anchor_write_journal`.
import type { WriteEntry, WriteJournal } from "@afr/store";
import type { Pool } from "pg";
import type { Hex } from "viem";

export class PgWriteJournal implements WriteJournal {
  readonly pool: Pool;
  constructor(pool: Pool) {
    this.pool = pool;
  }
  async get(id: Hex) {
    const { rows } = await this.pool.query("SELECT entry FROM anchor_write_journal WHERE id = $1", [
      id.toLowerCase(),
    ]);
    return rows[0]?.entry as WriteEntry | undefined;
  }
  /** Resolves after commit; Postgres fsyncs the WAL on commit. */
  async set(e: WriteEntry) {
    await this.pool.query(
      `INSERT INTO anchor_write_journal (id, entry) VALUES ($1, $2)
       ON CONFLICT (id) DO UPDATE SET entry = EXCLUDED.entry, updated_at = now()`,
      [e.id.toLowerCase(), JSON.stringify(e)],
    );
  }
}
