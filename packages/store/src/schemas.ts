// L3 §5 [NORMATIVE] Arkiv schemas. One declarative spec drives both the SDK `defineSchema` objects
// (Arkiv store) and the portable attribute types (memory/Postgres stores). Never hand-write
// attribute names elsewhere.
import { addr, bool, bytes, defineSchema, type Schema, str, u64 } from "@arkiv-network/sdk/schema";
import type { Hex } from "viem";

type AttrType = "str" | "u64" | "addr" | "bool";
interface AttrSpec {
  readonly type: AttrType;
  readonly indexed?: true;
  readonly optional?: true;
}

const s = { type: "str" } as const;
const si = { type: "str", indexed: true } as const;
const n = { type: "u64" } as const;
const ni = { type: "u64", indexed: true } as const;
const ai = { type: "addr", indexed: true } as const;
const bi = { type: "bool", indexed: true } as const;
const opt = <T extends AttrSpec>(x: T) => ({ ...x, optional: true }) as const;

/** Per schema: attributes and the name of its single `bytes()` payload column. */
export const SCHEMA_SPEC = {
  "afr.batch.v1": {
    payload: "frame",
    attrs: {
      agent_key: si,
      lane: ni,
      seq_from: ni,
      seq_to: ni,
      chain_root: si,
      prev_chain_root: s,
      batch_root: s,
      session_key: ai,
      epoch_id: n,
      record_count: n,
      privacy: n,
      has_tx: opt(bi),
      has_block: opt(bi),
      has_unapproved_tx: opt(bi),
      has_violation: opt(bi),
    },
  },
  "afr.delegation.v1": {
    payload: "statement",
    attrs: {
      agent_key: si,
      lane: ni,
      session_key: ai,
      delegator: ai,
      not_before: n,
      not_after: ni,
    },
  },
  "afr.revocation.v1": {
    payload: "statement",
    attrs: { agent_key: si, session_key: ai, effective_at: n },
  },
  "afr.agent.v1": {
    payload: "statement",
    attrs: { agent_key: si, agent_id: s, operator: ai, privacy: n, version: n },
  },
  "afr.keygrant.v1": {
    payload: "grant",
    attrs: { agent_key: si, epoch_id: ni, reader: si, kek_id: s },
  },
  "afr.readerkey.v1": {
    payload: "statement",
    attrs: { owner: ai, x25519: si },
  },
  "afr.anchor.v1": {
    payload: "manifest",
    attrs: { anchor_root: si, anchor_chain: ni, anchor_tx: si, epoch: ni, leaf_count: n },
  },
  "afr.checkpoint.v1": {
    payload: "statement",
    attrs: { agent_key: si, lane: ni, seq_to: ni, chain_root: si, anchor_root: si, anchor_tx: s },
  },
  "afr.attestation.v1": {
    payload: "statement",
    attrs: { agent_key: si, lane: ni, seq_to: ni, attestor: ai, verdict: ni },
  },
  "afr.action.v1": {
    payload: "proof",
    attrs: {
      agent_key: si,
      lane: ni,
      seq: ni,
      action_type: si,
      value_bucket: ni,
      counterparty: opt(ai),
      chain_id: ni,
      tx_hash: opt(si),
      approved: bi,
      record_hash: s,
    },
  },
} as const satisfies Record<string, { payload: string; attrs: Record<string, AttrSpec> }>;

export type AfrSchemaName = keyof typeof SCHEMA_SPEC;
export const SCHEMA_NAMES = Object.keys(SCHEMA_SPEC) as AfrSchemaName[];

type TsOf<T> = T extends { type: "str" }
  ? string
  : T extends { type: "u64" }
    ? bigint
    : T extends { type: "addr" }
      ? Hex
      : boolean;
type Spec<S extends AfrSchemaName> = (typeof SCHEMA_SPEC)[S]["attrs"];
type Req<S extends AfrSchemaName> = {
  [K in keyof Spec<S> as Spec<S>[K] extends { optional: true } ? never : K]: TsOf<Spec<S>[K]>;
};
type Opt<S extends AfrSchemaName> = {
  [K in keyof Spec<S> as Spec<S>[K] extends { optional: true } ? K : never]?: TsOf<Spec<S>[K]>;
};
/** Attribute values of a schema in plain TS types (u64 → bigint). The payload is separate. */
export type AttrsOf<S extends AfrSchemaName> = Req<S> & Opt<S>;

function column(spec: AttrSpec) {
  const base = { str, u64, addr, bool }[spec.type]();
  const indexed = spec.indexed ? base.indexed() : base;
  return spec.optional ? indexed.optional() : indexed;
}

/** SDK schema objects for the Arkiv store (payload column = `bytes()`). */
export const ARKIV_SCHEMAS = Object.fromEntries(
  SCHEMA_NAMES.map((name) => {
    const { attrs, payload } = SCHEMA_SPEC[name];
    const cols: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(attrs) as [string, AttrSpec][]) cols[k] = column(v);
    cols[payload] = bytes();
    return [name, defineSchema(name, cols as never)];
  }),
) as unknown as Record<AfrSchemaName, Schema>;
