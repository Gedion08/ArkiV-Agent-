// L8 §8 secrets at rest: the envelope scheme lives in @afr/secrets (the watcher opens watch keys too);
// the pre-v2 migration stays here.
import { aesGcmOpen } from "@afr/crypto";
import type { OrgSecrets } from "@afr/secrets";
import type { Pool } from "pg";

export * from "@afr/secrets";

/**
 * One-off: re-seals secrets written under the pre-v2 single master key (iv ‖ AES-GCM(master), no version
 * byte) into the per-org format. Idempotent; a row changed meanwhile is left alone.
 */
export async function migrateLegacySecrets(o: {
  pool: Pool;
  secrets: OrgSecrets;
  legacyMasterKey: Uint8Array;
}): Promise<{ migrated: number; current: number; failed: number }> {
  const n = { migrated: 0, current: 0, failed: 0 };
  const tables = [
    {
      select: `SELECT w.agent_id AS id, a.org_id, w.kms_ciphertext AS ct, a.agent_key AS aad
               FROM watch_keys w JOIN agents a ON a.id = w.agent_id`,
      update:
        "UPDATE watch_keys SET kms_ciphertext = $3 WHERE agent_id = $1 AND kms_ciphertext = $2",
      key: (r: Row) => [r.id],
    },
    {
      select: `SELECT s.agent_id AS id, s.address AS addr, a.org_id, s.presigned_revocation_kms AS ct, s.address AS aad
               FROM session_keys s JOIN agents a ON a.id = s.agent_id WHERE s.presigned_revocation_kms IS NOT NULL`,
      update: `UPDATE session_keys SET presigned_revocation_kms = $4
               WHERE agent_id = $1 AND address = $2 AND presigned_revocation_kms = $3`,
      key: (r: Row) => [r.id, r.addr],
    },
  ];
  type Row = { id: string; addr?: Buffer; org_id: string; ct: Buffer; aad: Buffer };
  for (const t of tables) {
    const { rows } = await o.pool.query<Row>(t.select);
    for (const r of rows) {
      try {
        await o.secrets.open(r.org_id, r.ct, r.aad);
        n.current++;
        continue;
      } catch {}
      try {
        const plain = aesGcmOpen(o.legacyMasterKey, r.ct.subarray(0, 12), r.ct.subarray(12), r.aad);
        const sealed = await o.secrets.seal(r.org_id, plain, r.aad);
        plain.fill(0);
        const u = await o.pool.query(t.update, [...t.key(r), r.ct, sealed]);
        if (u.rowCount) n.migrated++;
      } catch {
        n.failed++;
      }
    }
  }
  return n;
}
