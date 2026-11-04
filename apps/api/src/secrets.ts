// L8 §8 secrets at rest: per-org envelope keys. Each org gets a random AES-256 data key (DEK), stored only
// wrapped by the KEK (AWS KMS, bound to the org by encryption context). Secrets are sealed under the DEK:
// 0x01 ‖ iv(12) ‖ AES-256-GCM(dek, iv, plain, aad).
import { randomBytes } from "node:crypto";
import { aesGcmOpen, aesGcmSeal } from "@afr/crypto";
import { DecryptCommand, EncryptCommand, type KMSClient } from "@aws-sdk/client-kms";
import type { Pool } from "pg";

/** Wraps per-org data keys. Must bind the org id, so a DEK wrapped for one org can't be used for another. */
export interface KeyWrapper {
  wrapDataKey(dek: Uint8Array, orgId: string): Promise<Uint8Array>;
  unwrapDataKey(wrapped: Uint8Array, orgId: string): Promise<Uint8Array>;
}

const SEALED_V1 = 0x01;
const utf8 = (s: string) => new TextEncoder().encode(s);

/** AWS KMS (symmetric key); the org id goes in the encryption context, so KMS refuses a cross-org unwrap. */
export function kmsKeyWrapper(kms: KMSClient, keyId: string): KeyWrapper {
  const ctx = (orgId: string) => ({ afr_org: orgId });
  return {
    async wrapDataKey(dek, orgId) {
      const r = await kms.send(
        new EncryptCommand({ KeyId: keyId, Plaintext: dek, EncryptionContext: ctx(orgId) }),
      );
      if (!r.CiphertextBlob) throw new Error("KMS_ENCRYPT");
      return r.CiphertextBlob;
    },
    async unwrapDataKey(wrapped, orgId) {
      const r = await kms.send(
        new DecryptCommand({
          KeyId: keyId,
          CiphertextBlob: wrapped,
          EncryptionContext: ctx(orgId),
        }),
      );
      if (!r.Plaintext) throw new Error("KMS_DECRYPT");
      return r.Plaintext;
    },
  };
}

/** Dev/test KEK: one local AES-256-GCM master key (iv ‖ ct, AAD = org id). Not for production. */
export function localKeyWrapper(masterKey: Uint8Array): KeyWrapper {
  return {
    wrapDataKey: async (dek, orgId) => {
      const iv = randomBytes(12);
      return Buffer.concat([iv, aesGcmSeal(masterKey, iv, dek, utf8(orgId))]);
    },
    unwrapDataKey: async (w, orgId) =>
      aesGcmOpen(masterKey, w.subarray(0, 12), w.subarray(12), utf8(orgId)),
  };
}

export interface DekCacheOptions {
  /** Most unwrapped DEKs held at once (LRU beyond it). Default 1000. */
  maxCached?: number;
  /** An unwrapped DEK is re-fetched from the KEK after this long. Default 15 min. */
  ttlMs?: number;
  now?: () => number;
}

export class OrgSecrets {
  readonly #pool: Pool;
  readonly #kek: KeyWrapper;
  /** Map order is LRU order (oldest first); evicted keys are zeroed. */
  readonly #deks = new Map<string, { dek: Uint8Array; at: number }>();
  readonly #max: number;
  readonly #ttl: number;
  readonly #now: () => number;

  constructor(pool: Pool, kek: KeyWrapper, o: DekCacheOptions = {}) {
    this.#pool = pool;
    this.#kek = kek;
    this.#max = o.maxCached ?? 1000;
    this.#ttl = o.ttlMs ?? 15 * 60_000;
    this.#now = o.now ?? Date.now;
  }

  async #dek(orgId: string): Promise<Uint8Array> {
    const now = this.#now();
    const hit = this.#deks.get(orgId);
    if (hit) {
      this.#deks.delete(orgId);
      if (now - hit.at < this.#ttl) {
        this.#deks.set(orgId, hit);
        return hit.dek;
      }
      hit.dek.fill(0);
    }
    const read = async () =>
      (
        await this.#pool.query<{ dek_wrapped: Buffer | null }>(
          "SELECT dek_wrapped FROM orgs WHERE id = $1",
          [orgId],
        )
      ).rows[0];
    const row = await read();
    if (!row) throw new Error("ORG_MISSING");
    let wrapped = row.dek_wrapped;
    if (!wrapped) {
      const dek = randomBytes(32);
      const w = Buffer.from(await this.#kek.wrapDataKey(dek, orgId));
      dek.fill(0);
      // first writer wins; a concurrent loser re-reads the winner's DEK
      const set = await this.#pool.query(
        "UPDATE orgs SET dek_wrapped = $2 WHERE id = $1 AND dek_wrapped IS NULL",
        [orgId, w],
      );
      wrapped = set.rowCount ? w : ((await read())?.dek_wrapped ?? null);
      if (!wrapped) throw new Error("ORG_MISSING");
    }
    const dek = await this.#kek.unwrapDataKey(wrapped, orgId);
    this.#deks.set(orgId, { dek, at: now });
    for (const [k, v] of this.#deks) {
      if (this.#deks.size <= this.#max) break;
      this.#deks.delete(k);
      v.dek.fill(0);
    }
    return dek;
  }

  async seal(orgId: string, plain: Uint8Array, aad: Uint8Array): Promise<Buffer> {
    const iv = randomBytes(12);
    const ct = aesGcmSeal(await this.#dek(orgId), iv, plain, aad);
    return Buffer.concat([Buffer.from([SEALED_V1]), iv, ct]);
  }

  async open(orgId: string, sealed: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    if (sealed[0] !== SEALED_V1) throw new Error("SEALED_VERSION");
    return aesGcmOpen(await this.#dek(orgId), sealed.subarray(1, 13), sealed.subarray(13), aad);
  }
}

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
