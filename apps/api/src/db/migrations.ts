// L8 §3 schema, v0 subset (tenancy, agents, recorder keys, lanes, checkpoints, batch index, intents).
// Raw SQL over `pg` instead of Drizzle (lean v0, L8 §3 note). Migrations are append-only.
import type { Pool } from "pg";

const MIGRATIONS: string[] = [
  `CREATE TABLE orgs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL,
     plan text NOT NULL DEFAULT 'developer', region text NOT NULL DEFAULT 'us', created_at timestamptz NOT NULL DEFAULT now());
   CREATE TABLE users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), wallet bytea UNIQUE NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now());
   CREATE TABLE memberships (org_id uuid REFERENCES orgs, user_id uuid REFERENCES users,
     role text NOT NULL CHECK (role IN ('owner','admin','engineer','viewer','auditor')), PRIMARY KEY (org_id, user_id));
   CREATE TABLE siwe_nonces (nonce text PRIMARY KEY, expires_at timestamptz NOT NULL);
   CREATE TABLE sessions (token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users,
     csrf_hash bytea NOT NULL, expires_at timestamptz NOT NULL);
   CREATE TABLE agents (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), org_id uuid NOT NULL REFERENCES orgs,
     agent_id text NOT NULL UNIQUE, agent_key bytea NOT NULL UNIQUE, name text NOT NULL,
     privacy_level smallint NOT NULL DEFAULT 0 CHECK (privacy_level BETWEEN 0 AND 2),
     retention_days int NOT NULL DEFAULT 365, expiry_strategy text NOT NULL DEFAULT 'rolling',
     approval_threshold_cents bigint, status text NOT NULL DEFAULT 'active',
     created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
   CREATE INDEX agents_org ON agents (org_id);
   CREATE TABLE agent_lanes (agent_id uuid REFERENCES agents, lane int, last_seq numeric, last_chain_root bytea,
     last_batch_at timestamptz, last_heartbeat_at timestamptz, recorder_version text, heartbeat jsonb,
     PRIMARY KEY (agent_id, lane));
   CREATE TABLE recorder_keys (id text PRIMARY KEY, org_id uuid NOT NULL REFERENCES orgs,
     agent_id uuid NOT NULL REFERENCES agents, secret_hash bytea NOT NULL, lanes int[] NOT NULL,
     created_by uuid, created_at timestamptz NOT NULL DEFAULT now(), last_used_at timestamptz, revoked_at timestamptz);
   CREATE TABLE watch_keys (agent_id uuid PRIMARY KEY REFERENCES agents, kms_ciphertext bytea NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now(), rotated_at timestamptz);
   CREATE TABLE session_keys (agent_id uuid REFERENCES agents, lane int NOT NULL, address bytea,
     not_before timestamptz NOT NULL, not_after timestamptz NOT NULL, delegation_entity bytea NOT NULL,
     revoked_at timestamptz, presigned_revocation_kms bytea, PRIMARY KEY (agent_id, address));
   CREATE TABLE batches_index (agent_id uuid REFERENCES agents, lane int, seq_from numeric, seq_to numeric NOT NULL,
     entity_key bytea NOT NULL, arkiv_tx bytea, chain_root bytea NOT NULL, batch_root bytea NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (agent_id, lane, seq_from));
   CREATE TABLE checkpoints (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), agent_id uuid NOT NULL REFERENCES agents,
     lane int NOT NULL, seq_to numeric NOT NULL, chain_root bytea NOT NULL, batch_entity bytea NOT NULL,
     status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','validated','anchored','superseded','rejected')),
     received_at timestamptz NOT NULL DEFAULT now(), UNIQUE (agent_id, lane, seq_to));
   CREATE TABLE tx_intents (agent_id uuid REFERENCES agents, lane int, seq numeric, chain_id bigint NOT NULL,
     tx_commit bytea, nonce_commit bytea NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
     PRIMARY KEY (agent_id, lane, seq));
   CREATE TABLE audit_log (id bigserial PRIMARY KEY, org_id uuid, actor text NOT NULL, action text NOT NULL,
     target text, ip inet, at timestamptz NOT NULL DEFAULT now());`,
];

/** Applies pending migrations, one transaction each; an advisory lock keeps concurrent starts serial. */
export async function migrate(pool: Pool): Promise<void> {
  const c = await pool.connect();
  try {
    await c.query("SELECT pg_advisory_lock(7794095)");
    await c.query("CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY)");
    const { rows } = await c.query<{ v: number | null }>(
      "SELECT max(version) AS v FROM schema_migrations",
    );
    for (let v = rows[0]?.v ?? 0; v < MIGRATIONS.length; v++) {
      await c.query("BEGIN");
      try {
        await c.query(MIGRATIONS[v] as string);
        await c.query("INSERT INTO schema_migrations (version) VALUES ($1)", [v + 1]);
        await c.query("COMMIT");
      } catch (e) {
        await c.query("ROLLBACK");
        throw e;
      }
    }
  } finally {
    await c.query("SELECT pg_advisory_unlock(7794095)").catch(() => {});
    c.release();
  }
}
