// Delegation (L2 §9 "Delegations first", L3 §5) and agent-profile publishing. A batch is submitted
// only once every key in its session_keys has a published delegation (the Recorder gates the uploader).
import { AfrError, keccakJcs } from "@afr/core";
import { type EvidenceStore, type Expiry, encodeCanonical, type PutRequest } from "@afr/store";
import { encodeAbiParameters, type Hex, keccak256 } from "viem";
import type { Journal } from "./journal.js";
import type { KeyManager } from "./keys.js";

/**
 * Writes one entity and waits for it; a previous attempt (crash, lost response) holding the same
 * idempotency key reconciles instead of resending. Returns the entity key when the store knows it.
 */
export async function putOnce(store: EvidenceStore, req: PutRequest): Promise<Hex | undefined> {
  try {
    return (await store.await(await store.put(req))).key;
  } catch (err) {
    const code = (err as { code?: string })?.code;
    if (code !== "IDEMPOTENCY_CONFLICT" && code !== "LOST_RESPONSE" && code !== "TIMEOUT")
      throw err;
    const r = await store.reconcile({ store: store.kind, idempotencyKey: req.idempotencyKey });
    // shortcut: a reverted write keeps its id and stays stuck; a new id (rotation, version) recovers
    if (r.state === "reverted" || r.state === "uncertain")
      throw new AfrError("STATEMENT_PENDING", `${req.schema} write ${r.state}`);
    if (r.state === "confirmed") return r.ref.key;
    if (code !== "IDEMPOTENCY_CONFLICT") throw err;
    return undefined; // an earlier attempt holds this id (e.g. a keygrant sealed with other randomness)
  }
}

export interface PublishDelegationsOptions {
  journal: Journal;
  store: EvidenceStore;
  agentKey: Hex;
  lane: number;
  expiresAt: Expiry;
}

/** Publishes every signed, unpublished delegation in the journal, dead sessions' included. */
export async function publishDelegations(o: PublishDelegationsOptions): Promise<void> {
  for (const d of o.journal.delegationsToPublish()) {
    const sessionKey = d.address.toLowerCase() as Hex;
    const idempotencyKey = keccak256(
      encodeAbiParameters(
        [{ type: "string" }, { type: "bytes32" }, { type: "address" }],
        ["afr.delegation", o.agentKey, sessionKey],
      ),
    );
    const key = await putOnce(o.store, {
      schema: "afr.delegation.v1",
      attrs: {
        agent_key: o.agentKey,
        lane: BigInt(o.lane),
        session_key: sessionKey,
        delegator: d.delegator as Hex,
        not_before: BigInt(d.notBefore),
        not_after: BigInt(d.notAfter),
      },
      // the message as journaled (decimal strings for uint64/uint256) + the operator's EIP-712 sig
      payload: encodeCanonical({ message: JSON.parse(d.delegationJson), sig: d.delegationSig }),
      expiresAt: o.expiresAt,
      readonly: true,
      lock: true,
      permissionlessExtension: true,
      idempotencyKey,
    });
    // the payload is deterministic, so an id conflict can only be our own earlier write
    o.journal.markDelegationPublished(d.address, key ?? idempotencyKey);
  }
}

export interface PublishProfileOptions {
  journal: Journal;
  store: EvidenceStore;
  keys: KeyManager;
  agentId: string;
  agentKey: Hex;
  privacy: 0 | 1 | 2;
  retentionDays: number;
  readers: Hex[];
  writers: Hex[];
}

/**
 * Publishes `afr.agent.v1` when its content changed (version + 1). Only in operator_env mode; with
 * other delegation modes the dashboard signs and publishes the profile.
 */
export async function publishProfile(o: PublishProfileOptions): Promise<void> {
  const { journal } = o;
  const watched: Hex[] = []; // shortcut: no watched-address config yet, add with the P3 watcher
  const content = keccakJcs({
    privacy: o.privacy,
    retentionDays: o.retentionDays,
    readers: o.readers,
    writers: o.writers,
    watched,
  });
  const changed = journal.getMeta("profile_hash") !== content;
  if (!changed && journal.getMeta("profile_published") === "1") return;
  let version = BigInt(journal.getMeta("profile_version") ?? "0");
  if (changed) {
    version += 1n;
    // persisted first: a retry after a crash reuses the version, hence the same idempotency key
    journal.setMeta({
      profile_version: `${version}`,
      profile_hash: content,
      profile_published: "0",
    });
  }
  const profile = {
    agentKey: o.agentKey,
    privacyLevel: o.privacy,
    retentionDays: o.retentionDays,
    watchedHash: keccakJcs(watched),
    readersHash: keccakJcs(o.readers),
    version,
  };
  const signed = await o.keys.signAsOperator("AgentProfile", profile);
  if (!signed) return;
  await putOnce(o.store, {
    schema: "afr.agent.v1",
    attrs: {
      agent_key: o.agentKey,
      agent_id: o.agentId,
      operator: signed.signer,
      privacy: BigInt(o.privacy),
      version,
    },
    payload: encodeCanonical({
      profile: { ...profile, version: `${version}` },
      sig: signed.sig,
      writers: o.writers,
      readers: o.readers,
      ...(o.privacy >= 1 ? { watched } : {}),
    }),
    expiresAt: { days: 180 }, // Architecture §8 entity table: 180 days, renewed
    readonly: false,
    lock: false,
    permissionlessExtension: true,
    idempotencyKey: keccak256(
      encodeAbiParameters(
        [{ type: "string" }, { type: "bytes32" }, { type: "uint64" }],
        ["afr.agent", o.agentKey, version],
      ),
    ),
  });
  journal.setMeta({ profile_published: "1" });
}
