// Anchor loop (L5 §3.2). One leader drives at most one anchor at a time through
// building → manifest → sent → included → published, persisting each step before the next side effect:
//   - Arkiv writes (manifest, checkpoints) have idempotency keys derived from the root, and are
//     reconciled before any put, so a restart never writes them twice (WriterQueue rules, L3 §7);
//   - the Base tx is signed, journaled (raw + hash), then broadcast; a restart rebroadcasts those bytes.
//     The contract's DuplicateRoot is the last guard (A5).
import {
  AfrError,
  type AnchorLeaf,
  anchorProofs,
  anchorRoot,
  isLocalAgentId,
  parseAgentId,
  sortAnchorLeaves,
  typedData,
} from "@afr/core";
import type { Logger } from "@afr/log";
import { type EvidenceStore, type Expiry, encodeCanonical, type PutRequest } from "@afr/store";
import { concat, type Hex, keccak256, numberToHex, stringToHex } from "viem";
import type { AnchorChain } from "./chain.js";
import type { AnchorDb, AnchoredLeaf, AnchorRow, CheckpointRow, LeafJson } from "./db.js";
import { validateCheckpoint } from "./validate.js";

export interface AnchorAlert {
  code: "BROKEN_CHAIN" | "EQUIVOCATION" | "CHECKPOINT_REJECTED" | "ANCHOR_FAILED";
  agentKey?: Hex;
  lane?: number;
  seqTo?: bigint;
  detail?: string;
}

export interface AnchorServiceOptions {
  db: AnchorDb;
  store: EvidenceStore;
  chain: AnchorChain;
  now?: () => Date;
  /** L8 plan cadence; Arch §21 ANCHOR_CADENCE_S. */
  cadenceMs?: number;
  /** N_MAX (L5 §3.2): anchor early at this many (agent, lane) pairs, never more per anchor. */
  maxLeaves?: number;
  /** How long one tick waits for an anchor receipt before leaving it to the next tick. */
  receiptWaitMs?: number;
  /** A transient validation failure becomes a rejection after this long. */
  retryForMs?: number;
  /** shortcut: fixed lifetime; the rolling extension job (L5 §3.5) is a later ticket. */
  expiresAt?: Expiry;
  /** Watcher feed (BROKEN_CHAIN / EQUIVOCATION, L6). */
  onAlert?: (a: AnchorAlert) => void;
  logger?: Logger;
}

export interface TickResult {
  validated: number;
  rejected: number;
  /** The anchor this tick worked on, and the status it reached. */
  anchor?: { root: Hex; status: AnchorRow["status"] };
}

const leafOf = (l: LeafJson): AnchorLeaf => ({
  agentKey: l.agent_key,
  lane: l.lane,
  seqTo: BigInt(l.seq_to),
  chainRoot: l.chain_root,
});
const tag = (s: string) => stringToHex(s);
/** EIP-712 domain chain for statements about an agent (L1 §7); local dev agents use 8453. */
const identityChainId = (agentId: string) =>
  isLocalAgentId(agentId) ? 8453n : parseAgentId(agentId).chainId;

export class AnchorService {
  readonly o: Required<Omit<AnchorServiceOptions, "logger" | "onAlert">> & AnchorServiceOptions;

  constructor(o: AnchorServiceOptions) {
    this.o = {
      now: () => new Date(),
      cadenceMs: 600_000,
      maxLeaves: 500,
      retryForMs: 3_600_000,
      receiptWaitMs: 30_000,
      expiresAt: { days: 30 },
      ...o,
    };
  }

  #alert(a: AnchorAlert) {
    this.o.logger?.warn(
      { code: a.code, lane: a.lane, seq_to: a.seqTo?.toString() },
      "anchor alert",
    );
    this.o.onAlert?.(a);
  }

  async tick(): Promise<TickResult> {
    const v = await this.validatePending();
    let a = await this.o.db.openAnchor();
    if (!a) a = await this.#build();
    if (a) a = await this.#drive(a);
    await this.confirm();
    return { ...v, ...(a ? { anchor: { root: a.root, status: a.status } } : {}) };
  }

  /** pending → validated | rejected (transient failures wait, up to retryForMs). */
  async validatePending(): Promise<{ validated: number; rejected: number }> {
    const { db, store } = this.o;
    let validated = 0;
    let rejected = 0;
    for (const c of await db.checkpoints("pending", 1000)) {
      const v = await validateCheckpoint(store, c, await db.sessionKeys(c.agentKey, c.lane));
      if (v.ok) {
        await db.setCheckpointStatus([c.id], "validated");
        validated++;
      } else if (!v.retry || this.o.now().getTime() - c.receivedAt.getTime() > this.o.retryForMs) {
        await db.setCheckpointStatus([c.id], "rejected", v.reason);
        this.#alert({
          code: "CHECKPOINT_REJECTED",
          agentKey: c.agentKey,
          lane: c.lane,
          seqTo: c.seqTo,
          detail: v.reason,
        });
        rejected++;
      }
    }
    return { validated, rejected };
  }

  /** Picks the leaves (latest validated per (agent, lane), rewinds refused) and opens an anchor if due. */
  async #build(): Promise<AnchorRow | undefined> {
    const { db } = this.o;
    const groups = new Map<string, CheckpointRow[]>();
    for (const c of await db.checkpoints("validated", 100_000)) {
      const k = `${c.agentKey}:${c.lane}`;
      groups.set(k, [...(groups.get(k) ?? []), c]);
    }
    const leaves: LeafJson[] = [];
    for (const rows of groups.values()) {
      rows.sort((x, y) => (x.seqTo < y.seqTo ? 1 : -1)); // newest first: older ones are covered by its chain_root
      const best = rows[0] as CheckpointRow;
      const last = await db.lastAnchored(best.agentKey, best.lane);
      if (last && best.seqTo <= last.seqTo) {
        const same = best.seqTo === last.seqTo && best.chainRoot === last.chainRoot;
        if (same)
          await db.setCheckpointStatus(
            rows.map((r) => r.id),
            "superseded",
          );
        else {
          // a rewind (lower seq_to) or a different root at the same seq_to: never anchored
          const code = best.seqTo === last.seqTo ? "EQUIVOCATION" : "BROKEN_CHAIN";
          await db.setCheckpointStatus(
            rows.map((r) => r.id),
            "rejected",
            code,
          );
          this.#alert({
            code,
            agentKey: best.agentKey,
            lane: best.lane,
            seqTo: best.seqTo,
            detail: `last anchored seq_to ${last.seqTo}`,
          });
        }
        continue;
      }
      leaves.push({
        agent_id: best.agentId,
        agent_key: best.agentKey,
        lane: best.lane,
        seq_to: best.seqTo.toString(),
        chain_root: best.chainRoot,
        ids: rows.map((r) => r.id),
      });
    }
    if (!leaves.length) return undefined;
    const last = await db.lastAnchorAt();
    const due =
      !last ||
      this.o.now().getTime() - last.getTime() >= this.o.cadenceMs ||
      leaves.length >= this.o.maxLeaves;
    if (!due) return undefined;
    const chosen = sortAnchorLeaves(leaves.map(leafOf))
      .slice(0, this.o.maxLeaves)
      .map((l) => leaves.find((x) => x.agent_key === l.agentKey && x.lane === l.lane) as LeafJson);
    const root = anchorRoot(chosen.map(leafOf));
    const prior = await db.anchor(root);
    if (prior) {
      // same leaf set as an anchor that already exists (failed, or done but not yet marked): never re-anchor
      this.#alert({ code: "ANCHOR_FAILED", detail: `root ${root} already ${prior.status}` });
      return undefined;
    }
    const row: AnchorRow = {
      root,
      chainId: this.o.chain.chainId,
      contract: this.o.chain.o.contract,
      leaves: chosen,
      status: "building",
      createdAt: this.o.now(),
    };
    await db.insertAnchor(row);
    return row;
  }

  /** Moves one anchor forward until it waits on the chain or is published. */
  async #drive(a: AnchorRow): Promise<AnchorRow> {
    const { db, chain } = this.o;
    for (;;) {
      if (a.status === "building") {
        const ref = await this.#putOnce(this.#manifest(a));
        a = { ...a, status: "manifest", manifestKey: ref };
        await db.updateAnchor(a.root, { status: "manifest", manifestKey: ref });
      } else if (a.status === "manifest") {
        if ((await chain.epochOf(a.root)) !== 0n)
          throw new AfrError("ANCHOR_STATE", "root is anchored but no tx was journaled");
        const { raw, hash } = await chain.sign(a.root, a.leaves.length, a.manifestKey as Hex);
        await db.updateAnchor(a.root, { status: "sent", txHash: hash, rawTx: raw }); // journaled before broadcast
        a = { ...a, status: "sent", txHash: hash, rawTx: raw };
        await chain.broadcast(raw);
        await chain.settle(hash, this.o.receiptWaitMs);
      } else if (a.status === "sent") {
        let inc: Awaited<ReturnType<AnchorChain["inclusion"]>>;
        try {
          inc = await chain.inclusion(a.txHash as Hex, a.rawTx as Hex);
        } catch (e) {
          const reason = (e as { code?: string }).code ?? "ERROR";
          await db.updateAnchor(a.root, { status: "failed", reason });
          this.#alert({ code: "ANCHOR_FAILED", detail: `${a.txHash}: ${reason}` });
          return { ...a, status: "failed", reason };
        }
        if (inc === "pending") return a;
        if (inc === "unknown") {
          await chain.broadcast(a.rawTx as Hex); // the same bytes: never a second signature
          await chain.settle(a.txHash as Hex, this.o.receiptWaitMs);
          inc = await chain.inclusion(a.txHash as Hex, a.rawTx as Hex);
          if (inc === "pending" || inc === "unknown") return a;
        }
        if (inc === "dropped") {
          // our nonce went to another tx; sign again only if this root still has no epoch
          if ((await chain.epochOf(a.root)) !== 0n)
            throw new AfrError("ANCHOR_STATE", "root is anchored by a tx we didn't journal");
          a = { ...a, status: "manifest" };
          await db.updateAnchor(a.root, { status: "manifest" });
          continue;
        }
        a = { ...a, status: "included", ...inc };
        await db.updateAnchor(a.root, { status: "included", ...inc });
      } else if (a.status === "included") {
        await this.#publish(a);
        return { ...a, status: "published" };
      } else return a;
    }
  }

  #manifest(a: AnchorRow): PutRequest<"afr.anchor.v1"> {
    return {
      schema: "afr.anchor.v1",
      // the manifest precedes its tx (its key goes into anchorRoot), so anchor_tx/epoch are unknown here:
      // find the tx through Anchored(root) (L3 §5 note)
      attrs: {
        anchor_root: a.root,
        anchor_chain: a.chainId,
        anchor_tx: "",
        epoch: 0n,
        leaf_count: BigInt(a.leaves.length),
      },
      payload: encodeCanonical({
        anchor_root: a.root,
        chain_id: a.chainId.toString(),
        contract: a.contract,
        leaves: a.leaves.map(({ ids: _, agent_id: __, ...l }) => l),
      }),
      expiresAt: this.o.expiresAt,
      readonly: true,
      permissionlessExtension: true,
      lock: true,
      idempotencyKey: keccak256(concat([tag("afr/anchor-manifest"), a.root])),
    };
  }

  /** One afr.checkpoint.v1 per leaf (CheckpointStatement signed by the anchor key + proof), then the DB. */
  async #publish(a: AnchorRow) {
    const { chain } = this.o;
    const leaves = sortAnchorLeaves(a.leaves.map(leafOf));
    const proofs = anchorProofs(leaves);
    const out: AnchoredLeaf[] = [];
    for (const [i, l] of leaves.entries()) {
      const proof = proofs[i] as Hex[];
      const json = a.leaves.find(
        (x) => x.agent_key === l.agentKey && x.lane === l.lane,
      ) as LeafJson;
      const message = {
        agentKey: l.agentKey,
        lane: l.lane,
        seqTo: l.seqTo,
        chainRoot: l.chainRoot,
        anchorRoot: a.root,
        anchorChainId: a.chainId,
        anchorTx: a.txHash as Hex,
      };
      const sig = await chain.o.signer.signTypedData(
        typedData(identityChainId(json.agent_id), "CheckpointStatement", message) as never,
      );
      const entity = await this.#putOnce({
        schema: "afr.checkpoint.v1",
        attrs: {
          agent_key: l.agentKey,
          lane: BigInt(l.lane),
          seq_to: l.seqTo,
          chain_root: l.chainRoot,
          anchor_root: a.root,
          anchor_tx: a.txHash as Hex,
        },
        payload: encodeCanonical({
          statement: { ...message, seqTo: l.seqTo.toString(), anchorChainId: a.chainId.toString() },
          sig,
          proof,
          epoch: (a.epoch as bigint).toString(),
          contract: a.contract,
        }),
        expiresAt: this.o.expiresAt,
        readonly: true,
        permissionlessExtension: true,
        lock: true,
        idempotencyKey: keccak256(
          concat([tag("afr/checkpoint"), a.root, l.agentKey, numberToHex(l.lane, { size: 4 })]),
        ),
      });
      out.push({
        ids: json.ids,
        root: a.root,
        epoch: a.epoch as bigint,
        txHash: a.txHash as Hex,
        proof,
        entity,
      });
    }
    await this.o.db.markPublished(a.root, out);
  }

  /** Reconcile first; put only when the store has never seen this write. */
  async #putOnce<S extends PutRequest["schema"]>(req: PutRequest<S>): Promise<Hex> {
    const { store } = this.o;
    const write = { store: store.kind, idempotencyKey: req.idempotencyKey };
    const r = await store.reconcile(write);
    if (r.state === "confirmed") return r.ref.key;
    if (r.state === "uncertain")
      throw new AfrError("STORE_UNCERTAIN", "write outcome unknown; retry next tick");
    if (r.state === "reverted")
      throw new AfrError("STORE_REVERTED", "write reverted; needs an operator");
    return (await store.await(await store.put(req))).key;
  }

  /** published → safe → finalized by the chain's block tags. */
  async confirm(): Promise<void> {
    const { db, chain } = this.o;
    const open = await db.anchorsIn(["published", "safe"]);
    if (!open.length) return;
    const t = await chain.tags();
    for (const a of open) {
      const b = a.blockNumber as bigint;
      const next = b <= t.finalized ? "finalized" : b <= t.safe ? "safe" : a.status;
      if (next !== a.status) await db.updateAnchor(a.root, { status: next });
    }
  }
}
