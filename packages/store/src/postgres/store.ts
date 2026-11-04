// L3 §9 PostgresStore: Arkiv semantics over one table (readonly, lock, permissionless extension,
// MAX_LIFETIME, expiry, createdBy, keyset queries). Blocks are simulated from the injected clock.
// No third-party guarantees: verification relies on signatures + Base anchors.
import { AfrError, EVIDENCE_LOCK_ADDRESS } from "@afr/core";
import type { Pool, QueryResult } from "pg";
import { bytesToHex, type Hex } from "viem";
import { BLOCK_TIME_S, MAX_LIFETIME_BLOCKS, MemoryStore } from "../memory/store.js";
import { type PrivacyLevel, validatePut } from "../privacy.js";
import type { AfrSchemaName, AttrsOf } from "../schemas.js";
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
import { PG_SCHEMA_SQL } from "./schema.js";

const BLOCK_MS = BLOCK_TIME_S * 1000;
const err = (code: string, msg: string) => new AfrError(code, msg);
const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");
const lc = (h: Hex) => h.toLowerCase() as Hex;
const ts = (p: number) => `to_timestamp($${p}::double precision / 1000)`;
const COLS = `key, schema, attrs::text AS attrs, payload, owner, creator, readonly, permissionless_extension,
  (extract(epoch FROM created_at) * 1000)::bigint AS created_ms,
  (extract(epoch FROM expires_at) * 1000)::bigint AS expires_ms`;

interface Row {
  key: Buffer;
  schema: AfrSchemaName;
  attrs: string;
  payload: Buffer;
  owner: Buffer;
  creator: Buffer;
  readonly: boolean;
  permissionless_extension: boolean;
  created_ms: string;
  expires_ms: string;
}

/** jsonb text with bigints as exact JSON numbers (attrs are flat: string | bigint | boolean). */
const jsonValue = (v: unknown) => (typeof v === "bigint" ? v.toString() : JSON.stringify(v));
const attrsJson = (a: Record<string, unknown>) =>
  `{${Object.entries(a)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${JSON.stringify(k)}:${jsonValue(v)}`)
    .join(",")}}`;
/** Numbers come back as bigints, read from their source text (no float round-trip). */
const parseAttrs = (text: string) =>
  (
    JSON.parse as (
      t: string,
      r: (k: string, v: unknown, c: { source: string }) => unknown,
    ) => unknown
  )(text, (_k, v, c) => (typeof v === "number" ? BigInt(c.source) : v)) as Record<string, unknown>;

/** Creates (idempotently) the table, indexes and guard triggers. */
export async function migratePostgres(pool: Pool): Promise<void> {
  await pool.query(PG_SCHEMA_SQL);
}

export interface PostgresStoreOptions {
  pool: Pool;
  writer: Hex;
  privacyLevel?: PrivacyLevel;
  /** ms clock; blocks are now / BLOCK_TIME_S. */
  now?: () => number;
}

export class PostgresStore implements EvidenceStore {
  readonly kind = "postgres" as const;
  readonly writer: Hex;
  readonly privacyLevel: PrivacyLevel;
  readonly #pool: Pool;
  readonly #now: () => number;
  #closed = false;

  constructor(o: PostgresStoreOptions) {
    this.#pool = o.pool;
    this.writer = lc(o.writer);
    this.privacyLevel = o.privacyLevel ?? 0;
    this.#now = o.now ?? Date.now;
  }

  async #q<R extends object = Row>(text: string, params: unknown[]): Promise<QueryResult<R>> {
    if (this.#closed) throw err("CLOSED", "store closed");
    try {
      return await this.#pool.query<R>(text, params);
    } catch (e) {
      // the guard trigger raises "<CODE>: message"
      const m = /^(READONLY|NOT_OWNER): (.*)$/.exec((e as Error).message);
      throw m ? err(m[1] as string, m[2] as string) : e;
    }
  }

  #lifetimeMs(e: Expiry, now: number): number {
    const ms = "days" in e ? e.days * 86_400_000 : e.date.getTime() - now;
    if (ms <= 0) throw err("EXPIRY_INVALID", "expiry is in the past");
    if (BigInt(Math.ceil(ms / BLOCK_MS)) > MAX_LIFETIME_BLOCKS)
      throw err("EXPIRY_INVALID", `lifetime > MAX_LIFETIME ${MAX_LIFETIME_BLOCKS} blocks`);
    return ms;
  }

  #entity<S extends AfrSchemaName>(r: Row, payload = true): StoredEntity<S> {
    const createdAtBlock = BigInt(r.created_ms) / BigInt(BLOCK_MS);
    return {
      ref: { store: this.kind, key: bytesToHex(r.key), block: createdAtBlock },
      schema: r.schema as S,
      attrs: parseAttrs(r.attrs) as AttrsOf<S>,
      payload: payload ? new Uint8Array(r.payload) : new Uint8Array(0),
      meta: {
        owner: bytesToHex(r.owner),
        creator: bytesToHex(r.creator),
        createdAtBlock,
        expiresAtBlock: BigInt(r.expires_ms) / BigInt(BLOCK_MS),
        readonly: r.readonly,
        permissionlessExtension: r.permissionless_extension,
      },
    };
  }

  async #live(key: Hex): Promise<Row | undefined> {
    const r = await this.#q(
      `SELECT ${COLS} FROM evidence_entities WHERE key = $1 AND expires_at > ${ts(2)}`,
      [buf(key), this.#now()],
    );
    return r.rows[0];
  }

  async #byIdempotency(idempotencyKey: Hex): Promise<Row | undefined> {
    const r = await this.#q(`SELECT ${COLS} FROM evidence_entities WHERE idempotency_key = $1`, [
      buf(idempotencyKey),
    ]);
    return r.rows[0];
  }

  /** A single INSERT, idempotent on idempotency_key (L3 §9). */
  async put<S extends AfrSchemaName>(req: PutRequest<S>): Promise<PendingWrite> {
    if (this.#closed) throw err("CLOSED", "store closed");
    validatePut(req as PutRequest, this.privacyLevel);
    const now = this.#now();
    const expires = now + this.#lifetimeMs(req.expiresAt, now);
    const key = MemoryStore.keyFor(req.schema, req.idempotencyKey);
    const ins = await this.#q(
      `INSERT INTO evidence_entities (key, schema, attrs, payload, owner, creator, readonly,
         permissionless_extension, created_at, expires_at, idempotency_key)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, ${ts(9)}, ${ts(10)}, $11)
       ON CONFLICT (idempotency_key) DO NOTHING`,
      [
        buf(key),
        req.schema,
        attrsJson(req.attrs as Record<string, unknown>),
        Buffer.from(req.payload),
        buf(req.lock ? (EVIDENCE_LOCK_ADDRESS as Hex) : this.writer),
        buf(this.writer),
        req.readonly,
        req.permissionlessExtension,
        now,
        expires,
        buf(req.idempotencyKey),
      ],
    );
    if (!ins.rowCount) {
      const existing = await this.#byIdempotency(req.idempotencyKey);
      if (!existing?.payload.equals(req.payload))
        throw err("IDEMPOTENCY_CONFLICT", "idempotency key reused with different content");
    }
    return { store: this.kind, idempotencyKey: req.idempotencyKey, predictedKey: key };
  }

  async await(write: PendingWrite): Promise<EntityRef> {
    const r = await this.#byIdempotency(write.idempotencyKey);
    if (!r) throw err("NOT_FOUND", "unknown pending write");
    return this.#entity(r, false).ref;
  }

  async reconcile(write: PendingWrite): Promise<ReconcileOutcome> {
    const r = await this.#byIdempotency(write.idempotencyKey);
    return r ? { state: "confirmed", ref: this.#entity(r, false).ref } : { state: "not_sent" };
  }

  async get<S extends AfrSchemaName>(key: Hex, schema: S): Promise<StoredEntity<S> | null> {
    const r = await this.#live(key);
    return r && r.schema === schema ? this.#entity<S>(r) : null;
  }

  async *query<S extends AfrSchemaName>(q: StoreQuery<S>): AsyncIterable<StoredEntity<S>> {
    const pageSize = q.pageSize ?? 100;
    if (pageSize > 100) throw err("ATTR_INVALID", "pageSize ≤ 100");
    const now = this.#now();
    const pin = q.atBlock ?? BigInt(Math.floor(now / BLOCK_MS));
    const params: unknown[] = [q.schema, now, Number((pin + 1n) * BigInt(BLOCK_MS))];
    const p = (v: unknown) => `$${params.push(v)}`;
    const where = ["schema = $1", `expires_at > ${ts(2)}`, `created_at < ${ts(3)}`];
    if (q.createdBy) where.push(`creator = ANY(${p(q.createdBy.map(buf))}::bytea[])`);
    const eq: Record<string, unknown> = {};
    for (const [k, c] of Object.entries(q.where) as [string, Cond][]) {
      if ("eq" in c) {
        eq[k] = c.eq;
        continue;
      }
      const [lo, hi] = "gte" in c ? [c.gte] : "lte" in c ? [undefined, c.lte] : c.between;
      const a = `attrs->${p(k)}`;
      where.push(`jsonb_typeof(${a}) = 'number'`);
      if (lo !== undefined) where.push(`${a} >= ${p(lo.toString())}::jsonb`);
      if (hi !== undefined) where.push(`${a} <= ${p(hi.toString())}::jsonb`);
    }
    if (Object.keys(eq).length) where.push(`attrs @> ${p(attrsJson(eq))}::jsonb`); // GIN-indexed
    const dir = q.orderBy?.dir === "desc" ? "DESC" : "ASC";
    const sortKey = q.orderBy ? `(attrs->${p(q.orderBy.attr)}, key)` : "(key)";
    const order = q.orderBy ? `attrs->$${params.length} ${dir}, key ${dir}` : `key ${dir}`;
    const base = params.length;
    let cursor: Row | undefined;
    for (;;) {
      const page = [...params];
      let after = "";
      if (cursor) {
        const op = dir === "ASC" ? ">" : "<";
        after = q.orderBy
          ? ` AND ${sortKey} ${op} ($${base + 1}::jsonb, $${base + 2})`
          : ` AND key ${op} $${base + 1}`;
        if (q.orderBy) page.push(jsonValue(parseAttrs(cursor.attrs)[q.orderBy.attr] ?? null));
        page.push(cursor.key);
      }
      const r = await this.#q(
        `SELECT ${COLS} FROM evidence_entities WHERE ${where.join(" AND ")}${after} ORDER BY ${order} LIMIT ${pageSize}`,
        page,
      );
      for (const row of r.rows) yield this.#entity<S>(row, q.includePayload ?? true);
      if (r.rows.length < pageSize) return;
      cursor = r.rows.at(-1);
    }
  }

  async extend(key: Hex, expiresAt: Expiry): Promise<EntityRef> {
    const now = this.#now();
    const r = await this.#live(key);
    if (!r) throw err("NOT_FOUND", "entity not found or expired");
    if (lc(bytesToHex(r.owner)) !== this.writer && !r.permissionless_extension)
      throw err("NOT_OWNER", "only the owner may extend this entity");
    const target = now + this.#lifetimeMs(expiresAt, now);
    if (Math.floor(target / BLOCK_MS) <= Math.floor(Number(r.expires_ms) / BLOCK_MS))
      throw err("EXPIRY_NOT_EXTENDED", "expiry can only move later");
    await this.#q(`UPDATE evidence_entities SET expires_at = ${ts(2)} WHERE key = $1`, [
      r.key,
      target,
    ]);
    return {
      store: this.kind,
      key: bytesToHex(r.key),
      block: BigInt(r.created_ms) / BigInt(BLOCK_MS),
    };
  }

  /** Why an owner-only change matched no row. */
  async #missing(key: Hex): Promise<never> {
    throw (await this.#live(key))
      ? err("NOT_OWNER", "not the owner")
      : err("NOT_FOUND", "entity not found or expired");
  }

  /** Not on EvidenceStore; conformance C2. The guard trigger enforces readonly. */
  async patch(key: Hex, attrs: Record<string, unknown>): Promise<void> {
    const r = await this.#q(
      `UPDATE evidence_entities SET attrs = attrs || $2::jsonb
       WHERE key = $1 AND owner = $3 AND expires_at > ${ts(4)}`,
      [buf(key), attrsJson(attrs), buf(this.writer), this.#now()],
    );
    if (!r.rowCount) await this.#missing(key);
  }

  /** Not on EvidenceStore; conformance C3. The guard trigger also refuses locked rows. */
  async delete(key: Hex): Promise<void> {
    const r = await this.#q(
      `DELETE FROM evidence_entities WHERE key = $1 AND owner = $2 AND expires_at > ${ts(3)}`,
      [buf(key), buf(this.writer), this.#now()],
    );
    if (!r.rowCount) await this.#missing(key);
  }

  async head() {
    if (this.#closed) throw err("CLOSED", "store closed");
    const now = this.#now();
    return { block: BigInt(Math.floor(now / BLOCK_MS)), timestamp: Math.floor(now / 1000) };
  }

  /** The pool belongs to the caller. */
  async close() {
    this.#closed = true;
  }
}
