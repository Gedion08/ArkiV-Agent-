// L3 §3/§7 ArkivStore: EvidenceStore on Arkiv via the WriterQueue. Provenance never comes from
// $owner/$creator (D1); they're reported as metadata only.
import { AfrError, EVIDENCE_LOCK_ADDRESS } from "@afr/core";
import { ExpirationTime, MAX_LIFETIME, type PublicArkivClient } from "@arkiv-network/sdk";
import { and, asc, between, desc, eq, gte, lte } from "@arkiv-network/sdk/query";
import { addr, bool, bytes, u64 } from "@arkiv-network/sdk/schema";
import { bytesToHex, concat, type Hex, hexToBytes, keccak256, toHex } from "viem";
import { type PrivacyLevel, validatePut } from "../privacy.js";
import { type AfrSchemaName, ARKIV_SCHEMAS, type AttrsOf, SCHEMA_SPEC } from "../schemas.js";
import type {
  Cond,
  EntityRef,
  EvidenceStore,
  Expiry,
  PendingWrite,
  PutRequest,
  ReconcileOutcome,
  StoredEntity,
  StoreQuery,
} from "../types.js";
import { toStoreError } from "./errors.js";
import { WriterQueue } from "./writer-queue.js";

const BLOCK_TIME_S = 2;
const lc = (h: string) => h.toLowerCase() as Hex;
type Spec = Record<string, { type: "str" | "u64" | "addr" | "bool" }>;
interface Builder {
  createdBy(a: Hex): Builder;
  where(e: unknown): Builder;
  orderBy(o: unknown): Builder;
  limit(n: number): Builder;
  offset(n: number): Builder;
  fetch(): Promise<{ entities: Record<string, unknown>[] }>;
}

function expiration(e: Expiry) {
  const seconds = "days" in e ? e.days * 86_400 : Math.ceil((e.date.getTime() - Date.now()) / 1000);
  if (seconds <= 0) throw new AfrError("EXPIRY_INVALID", "expiry is in the past");
  if (BigInt(Math.ceil(seconds / BLOCK_TIME_S)) > MAX_LIFETIME)
    throw new AfrError(
      "EXPIRY_INVALID",
      "lifetime beyond Arkiv MAX_LIFETIME (≈ 182.5 d); use rolling expiry",
    );
  return "days" in e
    ? ExpirationTime.fromDays(e.days)
    : ExpirationTime.fromSeconds(seconds + (seconds % 2));
}

function typed(type: string, v: unknown) {
  if (type === "u64") return u64(v as bigint);
  if (type === "addr") return addr(v as Hex);
  if (type === "bool") return bool(v as boolean);
  return v as string;
}

export interface ArkivStoreOptions {
  queue: WriterQueue;
  publicClient: PublicArkivClient;
  privacyLevel?: PrivacyLevel;
  /** Readback attempts after a receipt (indexing delay). */
  readbackAttempts?: number;
}

export class ArkivStore implements EvidenceStore {
  readonly kind = "arkiv" as const;
  readonly #inflight = new Map<Hex, Promise<Hex>>();
  readonly #reqs = new Map<Hex, PutRequest>();
  #closed = false;

  readonly o: ArkivStoreOptions;
  constructor(o: ArkivStoreOptions) {
    this.o = o;
  }

  get writer() {
    return this.o.queue.address;
  }

  #open() {
    if (this.#closed) throw new AfrError("CLOSED", "store closed");
  }

  async put<S extends AfrSchemaName>(req: PutRequest<S>): Promise<PendingWrite> {
    this.#open();
    validatePut(req as PutRequest, this.o.privacyLevel ?? 0);
    const exp = expiration(req.expiresAt);
    const id = lc(req.idempotencyKey);
    const { attrs: spec, payload } = SCHEMA_SPEC[req.schema] as unknown as {
      attrs: Spec;
      payload: string;
    };
    const values: Record<string, unknown> = { [payload]: bytes(req.payload) };
    for (const [k, v] of Object.entries(req.attrs as Record<string, unknown>))
      if (v !== undefined) values[k] = typed((spec[k] as { type: string }).type, v);
    this.#reqs.set(id, req as PutRequest);
    const p = this.o.queue.run(id, async (wallet, entry) => {
      const [pred] = await this.o.publicClient.predictEntityKeys({ owner: this.writer, count: 1 });
      if (!pred) throw new AfrError("REVERTED", "key prediction failed");
      entry.predictedKey = pred.key;
      const r = await wallet.executeBatch(
        {
          creates: [
            {
              schema: ARKIV_SCHEMAS[req.schema],
              values: values as never,
              expiration: exp,
              flags: {
                readonly: req.readonly,
                permissionlessExtension: req.permissionlessExtension,
              },
              salt: pred.salt,
            },
          ],
          ownershipChanges: req.lock
            ? [{ entityKey: pred.key, newOwner: EVIDENCE_LOCK_ADDRESS as Hex }]
            : [],
        },
        WriterQueue.TX,
      );
      if (lc(r.createdEntities[0] ?? "0x") !== lc(pred.key))
        throw new AfrError("REVERTED", "created key differs from the predicted key");
      return pred.key;
    });
    p.catch(() => {});
    this.#inflight.set(id, p);
    return { store: this.kind, idempotencyKey: req.idempotencyKey };
  }

  async await(write: PendingWrite): Promise<EntityRef> {
    this.#open();
    const id = lc(write.idempotencyKey);
    const p = this.#inflight.get(id);
    if (!p) throw new AfrError("NOT_FOUND", "no in-flight write; use reconcile()");
    const key = await p.catch((e) => {
      throw toStoreError(e);
    });
    const entry = await this.o.queue.o.journal.get(id);
    await this.#verify(key, this.#reqs.get(id) as PutRequest);
    if (entry) await this.o.queue.o.journal.set({ ...entry, state: "verified" });
    return { store: this.kind, key, ...(entry?.txHash ? { txHash: entry.txHash } : {}) };
  }

  /** L3 §7 verify(): payload, attrs, flags and lock read back from the chain. */
  async #verify(key: Hex, req: PutRequest) {
    for (let i = 0; i < (this.o.readbackAttempts ?? 5); i++) {
      const e = await this.get(key, req.schema).catch(() => null);
      if (e) {
        const ok =
          bytesToHex(e.payload) === bytesToHex(req.payload) &&
          e.meta.readonly === req.readonly &&
          e.meta.permissionlessExtension === req.permissionlessExtension &&
          (!req.lock || lc(e.meta.owner) === lc(EVIDENCE_LOCK_ADDRESS)) &&
          Object.entries(req.attrs as Record<string, unknown>).every(([k, v]) => {
            const got = (e.attrs as Record<string, unknown>)[k];
            return typeof v === "string" ? lc(String(got)) === lc(v) : got === v;
          });
        if (!ok) throw new AfrError("REVERTED", "readback differs from the write");
        return;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new AfrError("TIMEOUT", "entity not readable after receipt");
  }

  async reconcile(write: PendingWrite): Promise<ReconcileOutcome> {
    this.#open();
    const id = lc(write.idempotencyKey);
    const r = await this.o.queue.reconcile(id);
    if (r.state !== "confirmed") return r;
    const e = await this.o.queue.o.journal.get(id);
    return {
      state: "confirmed",
      ref: {
        store: this.kind,
        key: e?.predictedKey as Hex,
        ...(e?.txHash ? { txHash: e.txHash } : {}),
      },
    };
  }

  #row<S extends AfrSchemaName>(
    schema: S,
    row: Record<string, unknown>,
    withPayload = true,
  ): StoredEntity<S> {
    const { attrs: spec, payload } = SCHEMA_SPEC[schema] as unknown as {
      attrs: Spec;
      payload: string;
    };
    const attrs: Record<string, unknown> = {};
    for (const k of Object.keys(spec)) {
      const v = (row[k] as { value: unknown } | undefined)?.value;
      if (v !== undefined) attrs[k] = spec[k]?.type === "addr" ? lc(v as string) : v;
    }
    const flags = row.$creationFlags as { readonly: boolean; permissionlessExtension: boolean };
    const p = row[payload] as { value: Hex } | undefined;
    return {
      ref: { store: this.kind, key: lc(row.$key as string), block: row.$createdAt as bigint },
      schema,
      attrs: attrs as AttrsOf<S>,
      payload: withPayload && p ? hexToBytes(p.value) : new Uint8Array(0),
      meta: {
        owner: lc(row.$owner as string),
        creator: lc(row.$creator as string),
        createdAtBlock: row.$createdAt as bigint,
        expiresAtBlock: row.$expiresAt as bigint,
        readonly: flags.readonly,
        permissionlessExtension: flags.permissionlessExtension,
      },
    };
  }

  async get<S extends AfrSchemaName>(key: Hex, schema: S): Promise<StoredEntity<S> | null> {
    this.#open();
    try {
      const row = await this.o.publicClient.getEntity(key, ARKIV_SCHEMAS[schema]);
      return this.#row(schema, row as Record<string, unknown>);
    } catch (e) {
      const name = (e as Error).name;
      if (name === "NoEntityFoundError" || name === "SchemaMismatchError") return null;
      throw toStoreError(e);
    }
  }

  async *query<S extends AfrSchemaName>(q: StoreQuery<S>): AsyncIterable<StoredEntity<S>> {
    this.#open();
    const pageSize = q.pageSize ?? 100;
    if (pageSize > 100) throw new AfrError("ATTR_INVALID", "pageSize ≤ 100");
    const spec = SCHEMA_SPEC[q.schema].attrs as unknown as Spec;
    const exprs = Object.entries(q.where).map(([k, c]) => {
      const t = (spec[k] as { type: string }).type;
      const cond = c as Cond;
      if ("eq" in cond) return eq(k, typed(t, cond.eq) as never);
      if ("gte" in cond) return gte(k, u64(cond.gte));
      if ("lte" in cond) return lte(k, u64(cond.lte));
      return between(k, u64(cond.between[0]), u64(cond.between[1]));
    });
    const writers = q.createdBy?.map(lc);
    // shortcut: offset paging (S7: correct, ordered) without block pinning (SDK 1.0.1 exposes no
    // atBlock); keyset pagination by seq_from is listBatches (evidence.ts).
    for (let offset = 0; ; offset += pageSize) {
      // Schema-generic: our attrs are typed by SCHEMA_SPEC, not the SDK's per-schema generics.
      let b = this.o.publicClient.select("*").from(ARKIV_SCHEMAS[q.schema]) as unknown as Builder;
      if (writers?.length === 1) b = b.createdBy(writers[0] as Hex);
      if (exprs.length)
        b = b.where(exprs.length === 1 ? (exprs[0] as never) : and(...(exprs as never[])));
      if (q.orderBy) b = b.orderBy((q.orderBy.dir === "asc" ? asc : desc)(q.orderBy.attr) as never);
      const page = await b
        .limit(pageSize)
        .offset(offset)
        .fetch()
        .catch((e) => {
          throw toStoreError(e);
        });
      for (const row of page.entities) {
        const e = this.#row(q.schema, row, q.includePayload ?? true);
        if (!writers || writers.includes(e.meta.creator)) yield e;
      }
      if (page.entities.length < pageSize) return;
    }
  }

  async extend(key: Hex, expiresAt: Expiry): Promise<EntityRef> {
    this.#open();
    const exp = expiration(expiresAt);
    const id = keccak256(concat([toHex("afr.extend"), key, toHex(Date.now(), { size: 8 })]));
    await this.o.queue
      .run(id, (w) => w.extendEntity({ entityKey: key, expiration: exp }, WriterQueue.TX))
      .catch((e) => {
        throw toStoreError(e);
      });
    return { store: this.kind, key };
  }

  /** Conformance only: AFR never patches or deletes evidence. Both fail in estimation, unsigned. */
  async patch(key: Hex, attrs: Record<string, unknown>): Promise<void> {
    const id = keccak256(concat([toHex("afr.patch"), key, toHex(Date.now(), { size: 8 })]));
    const e = await this.o.publicClient.getEntity(key).catch(() => null);
    const schema = ((e as { attributes?: Record<string, { value: string }> } | null)?.attributes?.[
      "arkiv.schema"
    ]?.value ?? "afr.batch.v1") as AfrSchemaName;
    const spec = SCHEMA_SPEC[schema].attrs as unknown as Spec;
    const set = Object.fromEntries(
      Object.entries(attrs).map(([k, v]) => [k, typed((spec[k] as { type: string }).type, v)]),
    );
    await this.o.queue
      .run(id, (w) => w.patchEntity(ARKIV_SCHEMAS[schema], key, { set } as never, WriterQueue.TX))
      .catch((err) => {
        throw toStoreError(err);
      });
  }

  async delete(key: Hex): Promise<void> {
    const id = keccak256(concat([toHex("afr.delete"), key, toHex(Date.now(), { size: 8 })]));
    await this.o.queue
      .run(id, (w) => w.deleteEntity({ entityKey: key }, WriterQueue.TX))
      .catch((e) => {
        throw toStoreError(e);
      });
  }

  async head() {
    this.#open();
    const b = await this.o.publicClient.getBlock({ blockTag: "latest" });
    return { block: b.number, timestamp: Number(b.timestamp) };
  }

  async close() {
    this.#closed = true;
  }
}
