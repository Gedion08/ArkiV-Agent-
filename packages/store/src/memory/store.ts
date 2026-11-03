// L3 §10 MemoryStore: Map-based, Arkiv semantics (readonly, lock, permissionless extension,
// MAX_LIFETIME, block-clock expiry, createdBy, ordered queries) plus failure injection.
import { AfrError, EVIDENCE_LOCK_ADDRESS } from "@afr/core";
import { concat, type Hex, keccak256, toHex } from "viem";
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

/** Same bound as Arkiv's MAX_LIFETIME (SPIKES S6): 7,884,000 blocks ≈ 182.5 d at 2 s. */
export const MAX_LIFETIME_BLOCKS = 7_884_000n;
export const BLOCK_TIME_S = 2;
const BLOCKS_PER_DAY = 86_400n / BigInt(BLOCK_TIME_S);

export type InjectedFailure = "timeout" | "revert" | "lost_response" | "429";

interface Row {
  schema: AfrSchemaName;
  attrs: Record<string, unknown>;
  payload: Uint8Array;
  owner: Hex;
  creator: Hex;
  createdAtBlock: bigint;
  expiresAtBlock: bigint;
  readonly: boolean;
  permissionlessExtension: boolean;
}

const err = (code: string, msg: string) => new AfrError(code, msg);
const lc = (h: Hex) => h.toLowerCase() as Hex;

/** The shared "chain": several MemoryStores (writers) see the same entities and clock. */
export class MemoryChain {
  readonly rows = new Map<Hex, Row>();
  block = 1n;
  readonly genesisTs = 1_790_000_000;
  advance(blocks: bigint | number) {
    this.block += BigInt(blocks);
  }
  timestamp() {
    return this.genesisTs + Number(this.block) * BLOCK_TIME_S;
  }
  live(key: Hex) {
    const r = this.rows.get(lc(key));
    return r && r.expiresAtBlock > this.block ? r : undefined;
  }
}

interface Pending {
  write: PendingWrite;
  outcome: "applied" | "reverted";
  failure?: InjectedFailure;
}

export class MemoryStore implements EvidenceStore {
  readonly kind = "memory" as const;
  readonly #pending = new Map<Hex, Pending>();
  readonly #fail: InjectedFailure[] = [];
  #closed = false;

  constructor(
    readonly chain: MemoryChain,
    readonly writer: Hex,
    readonly privacyLevel: PrivacyLevel = 0,
  ) {}

  /** Inject a failure into the next write (put → await). */
  failNext(kind: InjectedFailure) {
    this.#fail.push(kind);
  }

  #open() {
    if (this.#closed) throw err("CLOSED", "store closed");
  }

  #lifetime(e: Expiry): bigint {
    const blocks =
      "days" in e
        ? BigInt(e.days) * BLOCKS_PER_DAY
        : BigInt(Math.ceil((e.date.getTime() / 1000 - this.chain.timestamp()) / BLOCK_TIME_S));
    if (blocks <= 0n) throw err("EXPIRY_INVALID", "expiry is in the past");
    if (blocks > MAX_LIFETIME_BLOCKS)
      throw err(
        "EXPIRY_INVALID",
        `lifetime ${blocks} blocks > MAX_LIFETIME ${MAX_LIFETIME_BLOCKS}`,
      );
    return blocks;
  }

  /** Deterministic key, as in the Postgres store (L3 §9): keccak(schema ‖ idempotency_key). */
  static keyFor(schema: AfrSchemaName, idempotencyKey: Hex): Hex {
    return keccak256(concat([toHex(schema), lc(idempotencyKey)]));
  }

  async put<S extends AfrSchemaName>(req: PutRequest<S>): Promise<PendingWrite> {
    this.#open();
    validatePut(req as PutRequest, this.privacyLevel);
    const lifetime = this.#lifetime(req.expiresAt);
    const key = MemoryStore.keyFor(req.schema, req.idempotencyKey);
    const existing = this.chain.rows.get(key);
    if (existing) {
      const same =
        existing.payload.length === req.payload.length &&
        existing.payload.every((b, i) => b === req.payload[i]);
      if (!same) throw err("IDEMPOTENCY_CONFLICT", "idempotency key reused with different content");
      const write = { store: this.kind, idempotencyKey: req.idempotencyKey, predictedKey: key };
      this.#pending.set(lc(req.idempotencyKey), { write, outcome: "applied" });
      return write;
    }
    const failure = this.#fail.shift();
    if (failure === "429") throw err("RATE_LIMITED", "injected 429");
    const write: PendingWrite = {
      store: this.kind,
      idempotencyKey: req.idempotencyKey,
      predictedKey: key,
      txHash: keccak256(concat([key, toHex(this.chain.block, { size: 8 })])),
    };
    if (failure !== "revert") {
      this.chain.rows.set(key, {
        schema: req.schema,
        attrs: { ...(req.attrs as Record<string, unknown>) },
        payload: req.payload.slice(),
        owner: req.lock ? (EVIDENCE_LOCK_ADDRESS as Hex) : this.writer,
        creator: this.writer,
        createdAtBlock: this.chain.block,
        expiresAtBlock: this.chain.block + lifetime,
        readonly: req.readonly,
        permissionlessExtension: req.permissionlessExtension,
      });
    }
    this.#pending.set(lc(req.idempotencyKey), {
      write,
      outcome: failure === "revert" ? "reverted" : "applied",
      ...(failure ? { failure } : {}),
    });
    return write;
  }

  #ref(key: Hex, write?: PendingWrite): EntityRef {
    const row = this.chain.rows.get(key);
    return {
      store: this.kind,
      key,
      ...(write?.txHash ? { txHash: write.txHash } : {}),
      ...(row ? { block: row.createdAtBlock } : {}),
    };
  }

  async await(write: PendingWrite): Promise<EntityRef> {
    this.#open();
    const p = this.#pending.get(lc(write.idempotencyKey));
    if (!p) throw err("NOT_FOUND", "unknown pending write");
    const failure = p.failure;
    delete p.failure; // an injected failure fires once
    if (failure === "timeout") throw err("TIMEOUT", "injected timeout");
    if (failure === "lost_response") throw err("LOST_RESPONSE", "injected lost response");
    if (p.outcome === "reverted") throw err("REVERTED", "injected revert");
    return this.#ref(p.write.predictedKey as Hex, p.write);
  }

  async reconcile(write: PendingWrite): Promise<ReconcileOutcome> {
    this.#open();
    const p = this.#pending.get(lc(write.idempotencyKey));
    if (!p) return { state: "not_sent" };
    if (p.outcome === "reverted") return { state: "reverted", reason: "injected revert" };
    return { state: "confirmed", ref: this.#ref(p.write.predictedKey as Hex, p.write) };
  }

  #entity<S extends AfrSchemaName>(key: Hex, r: Row, payload = true): StoredEntity<S> {
    return {
      ref: { store: this.kind, key, block: r.createdAtBlock },
      schema: r.schema as S,
      attrs: { ...r.attrs } as AttrsOf<S>,
      payload: payload ? r.payload.slice() : new Uint8Array(0),
      meta: {
        owner: r.owner,
        creator: r.creator,
        createdAtBlock: r.createdAtBlock,
        expiresAtBlock: r.expiresAtBlock,
        readonly: r.readonly,
        permissionlessExtension: r.permissionlessExtension,
      },
    };
  }

  async get<S extends AfrSchemaName>(key: Hex, schema: S): Promise<StoredEntity<S> | null> {
    this.#open();
    const r = this.chain.live(key);
    return r && r.schema === schema ? this.#entity<S>(lc(key), r) : null;
  }

  async *query<S extends AfrSchemaName>(q: StoreQuery<S>): AsyncIterable<StoredEntity<S>> {
    this.#open();
    if ((q.pageSize ?? 100) > 100) throw err("ATTR_INVALID", "pageSize ≤ 100");
    const pin = q.atBlock ?? this.chain.block;
    const writers = q.createdBy?.map(lc);
    const match = (v: unknown, c: Cond) =>
      "eq" in c
        ? v === c.eq
        : "gte" in c
          ? typeof v === "bigint" && v >= c.gte
          : "lte" in c
            ? typeof v === "bigint" && v <= c.lte
            : typeof v === "bigint" && v >= c.between[0] && v <= c.between[1];
    const hits = [...this.chain.rows.entries()].filter(
      ([, r]) =>
        r.schema === q.schema &&
        r.createdAtBlock <= pin &&
        r.expiresAtBlock > this.chain.block &&
        (!writers || writers.includes(lc(r.creator))) &&
        Object.entries(q.where).every(([k, c]) => match(r.attrs[k], c as Cond)),
    );
    if (q.orderBy) {
      const { attr, dir } = q.orderBy;
      const sign = dir === "asc" ? 1 : -1;
      hits.sort(([ka, a], [kb, b]) => {
        const x = a.attrs[attr] as bigint | string;
        const y = b.attrs[attr] as bigint | string;
        return (x < y ? -1 : x > y ? 1 : ka < kb ? -1 : 1) * sign;
      });
    }
    for (const [key, r] of hits) yield this.#entity<S>(key, r, q.includePayload ?? true);
  }

  async extend(key: Hex, expiresAt: Expiry): Promise<EntityRef> {
    this.#open();
    const r = this.chain.live(key);
    if (!r) throw err("NOT_FOUND", "entity not found or expired");
    if (lc(r.owner) !== lc(this.writer) && !r.permissionlessExtension)
      throw err("NOT_OWNER", "only the owner may extend this entity");
    const target = this.chain.block + this.#lifetime(expiresAt);
    if (target <= r.expiresAtBlock) throw err("EXPIRY_NOT_EXTENDED", "expiry can only move later");
    r.expiresAtBlock = target;
    return this.#ref(lc(key));
  }

  /** Not on EvidenceStore (AFR never patches evidence); exists so conformance can prove C2. */
  async patch(key: Hex, attrs: Record<string, unknown>): Promise<void> {
    this.#open();
    const r = this.chain.live(key);
    if (!r) throw err("NOT_FOUND", "entity not found or expired");
    if (lc(r.owner) !== lc(this.writer)) throw err("NOT_OWNER", "not the owner");
    if (r.readonly) throw err("READONLY", "entity is readonly");
    Object.assign(r.attrs, attrs);
  }

  /** Not on EvidenceStore; exists so conformance can prove C3. */
  async delete(key: Hex): Promise<void> {
    this.#open();
    const r = this.chain.live(key);
    if (!r) throw err("NOT_FOUND", "entity not found or expired");
    if (lc(r.owner) !== lc(this.writer)) throw err("NOT_OWNER", "not the owner");
    this.chain.rows.delete(lc(key));
  }

  async head() {
    this.#open();
    return { block: this.chain.block, timestamp: this.chain.timestamp() };
  }

  async close() {
    this.#closed = true;
  }
}
