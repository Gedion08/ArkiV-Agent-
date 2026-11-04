// L8 §1 tenancy. Queries filter by org (first line); `inOrg` also runs them as the `afr_app` role with
// `app.org_id` set, so Postgres RLS hides every other org's rows even if a WHERE is missing (second line).
// System lookups that must cross orgs (auth, a user's own memberships) use the pool directly.
import type { Pool, PoolClient } from "pg";

export type Q = Pick<PoolClient, "query">;

async function tx<T>(pool: Pool, orgId: string | undefined, fn: (q: Q) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    if (orgId) {
      await c.query("SET LOCAL ROLE afr_app");
      await c.query("SELECT set_config('app.org_id', $1, true)", [orgId]);
    }
    const out = await fn(c);
    await c.query("COMMIT");
    return out;
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}

/** One transaction scoped to an org: RLS applies. */
export const inOrg = <T>(pool: Pool, orgId: string, fn: (q: Q) => Promise<T>) =>
  tx(pool, orgId, fn);

/** One unscoped (system) transaction. */
export const inTx = <T>(pool: Pool, fn: (q: Q) => Promise<T>) => tx(pool, undefined, fn);
