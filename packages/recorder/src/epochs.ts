// Epoch KEK lifecycle (L4 §2, §7.4) and keygrant publishing (L4 §5).
// A KEK lives for one UTC month (epoch_id = month·16 + rotation) and rotates early when a reader is
// removed, the DEK-wrap budget runs low, or an operator asks. Every reader in the epoch gets a
// keygrant before the first batch of that epoch is submitted (the Recorder gates the uploader).
import { AfrError, epochIdFor } from "@afr/core";
import { type EpochKek, KEK_MAX_WRAPS, newEpochKek } from "@afr/crypto";
import type { Logger } from "@afr/log";
import { type EvidenceStore, type Expiry, encodeCanonical } from "@afr/store";
import { concat, encodeAbiParameters, type Hex, keccak256 } from "viem";
import type { Journal } from "./journal.js";
import type { SessionKey } from "./keys.js";

/** L4 §12 `sealKeygrant`: HPKE base mode to the reader's X25519 key (enc 32 B, ct 48 B). */
export type KeygrantSealer = (
  kek: EpochKek,
  readerPub: Hex,
  agentKey: Hex,
) => { enc: Uint8Array; ct: Uint8Array };

/** One seal() may wrap up to ~1,000 DEKs; rotate well before the L4 §4 IV budget. */
const WRAP_MARGIN = 4096;

export type RotationReason = "MONTH" | "WRAP_BUDGET" | "READER_REMOVED" | "MANUAL";

const norm = (readers: readonly string[]) =>
  [...new Set(readers.map((r) => r.toLowerCase() as Hex))].sort();

export interface EpochManagerOptions {
  journal: Journal;
  agentKey: Hex;
  readers: readonly string[];
  now: () => number;
  random: (n: number) => Uint8Array;
  logger?: Logger;
}

export class EpochManager {
  readonly #o: EpochManagerOptions;
  #readers: Hex[];

  constructor(o: EpochManagerOptions) {
    this.#o = o;
    this.#readers = norm(o.readers);
    this.setReaders(o.readers); // config may have changed since the last run
  }

  get readers(): Hex[] {
    return [...this.#readers];
  }

  /** The KEK to encrypt with now; creates (and persists, sealed) a new epoch when one is due. */
  current(): EpochKek {
    const { journal } = this.#o;
    const now = new Date(this.#o.now());
    const month = epochIdFor(now) >> 4;
    const latest = journal.latestEpoch();
    if (latest && !latest.rotatedAt && latest.epochId >> 4 === month) {
      if (latest.wraps < KEK_MAX_WRAPS - WRAP_MARGIN) return journal.epochKek(latest.epochId);
      this.#markRotated(latest.epochId, "WRAP_BUDGET");
    } else if (latest && !latest.rotatedAt) this.#markRotated(latest.epochId, "MONTH");
    const rotation = latest && latest.epochId >> 4 === month ? (latest.epochId & 15) + 1 : 0;
    const kek = newEpochKek(this.#o.agentKey, epochIdFor(now, rotation), this.#o.random);
    journal.putEpoch(kek, this.#readers);
    return kek;
  }

  /** Manual rotation (`fr keys rotate-epoch`, suspected compromise): the next batch uses a new KEK. */
  rotate(reason: RotationReason = "MANUAL"): void {
    const latest = this.#o.journal.latestEpoch();
    if (latest && !latest.rotatedAt) this.#markRotated(latest.epochId, reason);
  }

  #markRotated(epochId: number, reason: RotationReason) {
    this.#o.journal.markRotated(epochId);
    this.#o.logger?.info({ code: "EPOCH_ROTATED", reason, epoch_id: epochId }, "epoch rotated");
  }

  /**
   * L4 §7.1/§7.3: a removed reader rotates the epoch immediately (the new KEK is never granted to
   * it); an added reader gets a grant for the current epoch.
   */
  setReaders(readers: readonly string[]): void {
    const next = norm(readers);
    this.#readers = next;
    const latest = this.#o.journal.latestEpoch();
    if (!latest || latest.rotatedAt) return;
    if (latest.readers.some((r) => !next.includes(r))) this.rotate("READER_REMOVED");
    else if (next.some((r) => !latest.readers.includes(r)))
      this.#o.journal.setEpochReaders(latest.epochId, next);
  }

  noteWraps(epochId: number, n: number): void {
    this.#o.journal.addWraps(epochId, n);
  }

  /** Uploader gate: the epoch's keygrants are all confirmed. */
  grantsReady(epochId: number): boolean {
    return this.#o.journal.epoch(epochId)?.grantsPublished ?? false;
  }
}

export interface PublishGrantsOptions {
  journal: Journal;
  store: EvidenceStore;
  agentKey: Hex;
  session: SessionKey;
  sealKeygrant?: KeygrantSealer;
  expiresAt: Expiry;
}

/** Idempotency key per (agent, epoch, reader): one keygrant entity each. */
export function keygrantId(agentKey: Hex, epochId: number, reader: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "string" }, { type: "bytes32" }, { type: "uint32" }, { type: "bytes32" }],
      ["afr.keygrant", agentKey, epochId, reader],
    ),
  );
}

/**
 * Publishes the missing keygrants of every epoch still awaiting them (L4 §5). Grants are signed by
 * the current session key (delegation scope bit 4). Throws KEYGRANT_UNAVAILABLE without an HPKE sealer.
 */
export async function publishKeygrants(o: PublishGrantsOptions): Promise<void> {
  const { journal, store, agentKey } = o;
  for (const e of journal.epochsAwaitingGrants()) {
    const todo = e.readers.filter((r) => !e.granted.includes(r));
    if (!todo.length) continue;
    if (!o.sealKeygrant)
      throw new AfrError("KEYGRANT_UNAVAILABLE", "readers configured but no HPKE keygrant sealer");
    const kek = journal.epochKek(e.epochId);
    for (const reader of todo) {
      const idempotencyKey = keygrantId(agentKey, e.epochId, reader);
      const { enc, ct } = o.sealKeygrant(kek, reader, agentKey);
      const statement = {
        agentKey,
        epochId: e.epochId,
        kekId: kek.kekId,
        reader,
        encHash: keccak256(concat([enc, ct])),
      };
      const sig = await o.session.signStatement("KeyGrant", statement);
      try {
        await store.await(
          await store.put({
            schema: "afr.keygrant.v1",
            attrs: { agent_key: agentKey, epoch_id: BigInt(e.epochId), reader, kek_id: kek.kekId },
            payload: encodeCanonical({ enc, ct, statement, sig }),
            expiresAt: o.expiresAt,
            // L4 §5: deletable by the writer for crypto-shredding (§8)
            readonly: true,
            lock: false,
            permissionlessExtension: false,
            idempotencyKey,
          }),
        );
      } catch (err) {
        // a previous attempt (crash, lost response) already holds this id: reconcile, never resend
        const code = (err as { code?: string })?.code;
        if (code !== "IDEMPOTENCY_CONFLICT" && code !== "LOST_RESPONSE" && code !== "TIMEOUT")
          throw err;
        const r = await store.reconcile({ store: store.kind, idempotencyKey });
        // shortcut: a reverted grant keeps its id and stays stuck; rotate the epoch to recover
        if (r.state === "reverted" || r.state === "uncertain")
          throw new AfrError("KEYGRANT_PENDING", `keygrant write ${r.state}`);
        if (r.state === "not_sent" && code !== "IDEMPOTENCY_CONFLICT") throw err;
      }
      journal.markReaderGranted(e.epochId, reader);
    }
  }
}
