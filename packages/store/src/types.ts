// L3 §3 EvidenceStore interface.
import type { Hex } from "viem";
import type { AfrSchemaName, AttrsOf } from "./schemas.js";

export type StoreKind = "arkiv" | "postgres" | "memory";

/** Codes: PRIVACY_ATTR, SCHEMA_NOT_ALLOWED, ATTR_INVALID, PAYLOAD_TOO_LARGE, EXPIRY_INVALID, READONLY, NOT_OWNER, NOT_FOUND, EXPIRED, EXPIRY_NOT_EXTENDED, IDEMPOTENCY_CONFLICT, TIMEOUT, REVERTED, RATE_LIMITED, LOST_RESPONSE, CLOSED. */
export type StoreErrorCode =
  | "PRIVACY_ATTR"
  | "SCHEMA_NOT_ALLOWED"
  | "ATTR_INVALID"
  | "PAYLOAD_TOO_LARGE"
  | "EXPIRY_INVALID"
  | "READONLY"
  | "NOT_OWNER"
  | "NOT_FOUND"
  | "EXPIRED"
  | "EXPIRY_NOT_EXTENDED"
  | "IDEMPOTENCY_CONFLICT"
  | "TIMEOUT"
  | "REVERTED"
  | "RATE_LIMITED"
  | "LOST_RESPONSE"
  | "CLOSED";

export type Expiry = { days: number } | { date: Date };

export interface PutRequest<S extends AfrSchemaName = AfrSchemaName> {
  schema: S;
  attrs: AttrsOf<S>;
  /** The frame / statement bytes (≤ BATCH_MAX_FRAME_BYTES). */
  payload: Uint8Array;
  expiresAt: Expiry;
  /** AFR evidence is always readonly; the agent profile is the exception. */
  readonly: boolean;
  permissionlessExtension: boolean;
  /** Evidence lock (ADR-011). */
  lock: boolean;
  /** e.g. batch_id; reconciliation key. */
  idempotencyKey: Hex;
}

export interface EntityRef {
  store: StoreKind;
  key: Hex;
  txHash?: Hex;
  block?: bigint;
}

export interface EntityMeta {
  owner: Hex;
  creator: Hex;
  createdAtBlock: bigint;
  expiresAtBlock: bigint;
  readonly: boolean;
  permissionlessExtension: boolean;
}

export interface StoredEntity<S extends AfrSchemaName = AfrSchemaName> {
  ref: EntityRef;
  schema: S;
  attrs: AttrsOf<S>;
  payload: Uint8Array;
  meta: EntityMeta;
}

/** Portable condition subset (eq / gte / lte / between). */
export type Cond =
  | { eq: string | bigint | boolean }
  | { gte: bigint }
  | { lte: bigint }
  | { between: [bigint, bigint] };

export interface StoreQuery<S extends AfrSchemaName = AfrSchemaName> {
  schema: S;
  where: Partial<Record<keyof AttrsOf<S> & string, Cond>>;
  /** Discovery filter (writers declared in the agent profile). */
  createdBy?: Hex[];
  orderBy?: { attr: keyof AttrsOf<S> & string; dir: "asc" | "desc" };
  /** ≤ 100. */
  pageSize?: number;
  /** Pin for consistent pagination. */
  atBlock?: bigint;
  /** Default true. */
  includePayload?: boolean;
}

export interface PendingWrite {
  store: StoreKind;
  idempotencyKey: Hex;
  /** Known once signed/submitted. */
  predictedKey?: Hex;
  txHash?: Hex;
}

export type ReconcileOutcome =
  | { state: "confirmed"; ref: EntityRef }
  | { state: "not_sent" }
  | { state: "uncertain" }
  | { state: "reverted"; reason: string };

export interface EvidenceStore {
  readonly kind: StoreKind;
  /** Returns as soon as the durable intent is recorded. */
  put<S extends AfrSchemaName>(req: PutRequest<S>): Promise<PendingWrite>;
  /** Receipt + readback verified. */
  await(write: PendingWrite): Promise<EntityRef>;
  /** After crash/restart. */
  reconcile(write: PendingWrite): Promise<ReconcileOutcome>;
  get<S extends AfrSchemaName>(key: Hex, schema: S): Promise<StoredEntity<S> | null>;
  /** Keyset pagination internally. */
  query<S extends AfrSchemaName>(q: StoreQuery<S>): AsyncIterable<StoredEntity<S>>;
  extend(key: Hex, expiresAt: Expiry): Promise<EntityRef>;
  head(): Promise<{ block: bigint; timestamp: number }>;
  close(): Promise<void>;
}
