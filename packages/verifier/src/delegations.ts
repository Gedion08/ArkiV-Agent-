// L1 §7 delegations and revocations from the evidence store, each checked against the agent's operator
// (EIP-712, operator as of notBefore / effectiveAt). Arkiv is open-write: entities that don't verify are
// returned as `invalid`, never used. Shared by verifyAgent and the watcher's batch reconciliation (L6 §4.1).
import {
  AfrError,
  agentKey as agentKeyOf,
  DELEGATION_SCOPE,
  EIP712_TYPES,
  isLocalAgentId,
  parseAgentId,
  type StatementType,
  typedData,
} from "@afr/core";
import { decodeCanonical, type EvidenceStore } from "@afr/store";
import type { Hex, TypedDataDefinition } from "viem";
import type { IdentityReader } from "./readers.js";

export interface Delegation {
  lane: number;
  scope: number;
  /** unix seconds */
  notBefore: bigint;
  notAfter: bigint;
}

export interface DelegationSet {
  /** Lowercase session key → its valid delegations. */
  delegations: Map<Hex, Delegation[]>;
  /** Lowercase session key → the earliest valid revocation's effectiveAt (unix s). */
  revokedAt: Map<Hex, bigint>;
  /** Entity keys of delegations that failed validation. */
  invalid: Hex[];
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const lower = (h: unknown) => (typeof h === "string" ? (h.toLowerCase() as Hex) : undefined);
const decode = (payload: Uint8Array): Record<string, unknown> | undefined => {
  try {
    const d = decodeCanonical(payload);
    return isObj(d) ? d : undefined;
  } catch {
    return undefined;
  }
};

/** EIP-712 typed data from a JSON-boundary message (uint fields as decimal strings → bigint). */
export function typedStatement(chainId: bigint, type: StatementType, m: Record<string, unknown>) {
  const msg = Object.fromEntries(
    EIP712_TYPES[type].map(({ name, type: t }) => {
      const v = m[name];
      return [name, t.startsWith("uint") && typeof v === "string" ? BigInt(v) : v];
    }),
  );
  return typedData(chainId, type, msg) as unknown as TypedDataDefinition;
}

export const identityChainId = (agentId: string) =>
  isLocalAgentId(agentId) ? 8453n : parseAgentId(agentId).chainId;

/** Infra errors (AfrError from the identity reader) propagate; malformed or badly signed entities don't. */
export async function loadDelegations(
  agentId: string,
  o: { store: EvidenceStore; identity: IdentityReader; writers?: Hex[] },
): Promise<DelegationSet> {
  const ak = agentKeyOf(agentId);
  const chainId = identityChainId(agentId);
  const opSig = (td: TypedDataDefinition, sig: unknown, ts: bigint) =>
    typeof sig === "string" ? o.identity.isOperatorSig(agentId, td, sig as Hex, ts) : false;
  const out: DelegationSet = { delegations: new Map(), revokedAt: new Map(), invalid: [] };
  for await (const e of o.store.query({
    schema: "afr.delegation.v1",
    where: { agent_key: { eq: ak } },
    ...(o.writers ? { createdBy: o.writers } : {}),
  })) {
    const d = decode(e.payload);
    const m = d?.message;
    const sk = lower(isObj(m) ? m.sessionKey : undefined);
    let ok = false;
    try {
      ok =
        isObj(m) &&
        sk !== undefined &&
        lower(m.agentKey) === ak &&
        sk === e.attrs.session_key.toLowerCase() &&
        BigInt(m.lane as string) === e.attrs.lane &&
        (await opSig(
          typedStatement(chainId, "Delegation", m),
          d?.sig,
          BigInt(m.notBefore as string),
        ));
    } catch (err) {
      if (err instanceof AfrError) throw err;
    }
    if (!ok || !isObj(m) || !sk) {
      out.invalid.push(e.ref.key);
      continue;
    }
    // shortcut: depth-1 only (operator → session key); identity-key sub-delegation (L1 §7.1) lands with that recorder mode
    out.delegations.set(sk, [
      ...(out.delegations.get(sk) ?? []),
      {
        lane: Number(m.lane),
        scope: Number(m.scope),
        notBefore: BigInt(m.notBefore as string),
        notAfter: BigInt(m.notAfter as string),
      },
    ]);
  }
  for await (const e of o.store.query({
    schema: "afr.revocation.v1",
    where: { agent_key: { eq: ak } },
  })) {
    const d = decode(e.payload);
    const m = d?.message;
    const sk = lower(isObj(m) ? m.sessionKey : undefined);
    try {
      if (!isObj(m) || !sk || lower(m.agentKey) !== ak) continue;
      const at = BigInt(m.effectiveAt as string);
      if (!(await opSig(typedStatement(chainId, "Revocation", m), d?.sig, at))) continue;
      const prev = out.revokedAt.get(sk);
      if (prev === undefined || at < prev) out.revokedAt.set(sk, at);
    } catch (err) {
      if (err instanceof AfrError) throw err;
    }
  }
  return out;
}

/** The valid delegations that let `sk` sign records on `lane`. */
export const recordDelegations = (
  set: Pick<DelegationSet, "delegations">,
  sk: Hex,
  lane: number,
): Delegation[] =>
  (set.delegations.get(sk.toLowerCase() as Hex) ?? []).filter(
    (d) => d.lane === lane && (d.scope & DELEGATION_SCOPE.RECORDS) !== 0,
  );
