// L3 §9 Postgres schema. Attribute numbers are jsonb numbers (exact numerics), so `attrs->k`
// compares and orders them numerically; the triggers mirror Arkiv's readonly flag and evidence lock.
import { EVIDENCE_LOCK_ADDRESS } from "@afr/core";

export const PG_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS evidence_entities (
  key            bytea PRIMARY KEY,
  schema         text NOT NULL,
  attrs          jsonb NOT NULL,
  payload        bytea NOT NULL,
  owner          bytea NOT NULL,
  creator        bytea NOT NULL,
  readonly       boolean NOT NULL,
  permissionless_extension boolean NOT NULL,
  created_at     timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  idempotency_key bytea NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ee_batch ON evidence_entities
  (schema, (attrs->>'agent_key'), ((attrs->>'lane')::numeric), ((attrs->>'seq_from')::numeric));
CREATE INDEX IF NOT EXISTS ee_attrs ON evidence_entities USING gin (attrs jsonb_path_ops);

CREATE OR REPLACE FUNCTION afr_evidence_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.owner = '\\x${EVIDENCE_LOCK_ADDRESS.slice(2).toLowerCase()}'::bytea THEN
      RAISE EXCEPTION 'NOT_OWNER: entity is locked';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.readonly AND (NEW.attrs IS DISTINCT FROM OLD.attrs OR NEW.payload IS DISTINCT FROM OLD.payload) THEN
    RAISE EXCEPTION 'READONLY: entity is readonly';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ee_guard ON evidence_entities;
CREATE TRIGGER ee_guard BEFORE UPDATE OR DELETE ON evidence_entities
  FOR EACH ROW EXECUTE FUNCTION afr_evidence_guard();
`;
