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

export class OrgSecrets {
  readonly #pool: Pool;
  readonly #kek: KeyWrapper;
  // shortcut: unwrapped DEKs cached for the process lifetime, add an LRU + TTL when orgs number in the 10k+
  readonly #deks = new Map<string, Uint8Array>();

  constructor(pool: Pool, kek: KeyWrapper) {
    this.#pool = pool;
    this.#kek = kek;
  }

  async #dek(orgId: string): Promise<Uint8Array> {
    const cached = this.#deks.get(orgId);
    if (cached) return cached;
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
    this.#deks.set(orgId, dek);
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
