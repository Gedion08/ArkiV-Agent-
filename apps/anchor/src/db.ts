// Anchor service state (L5 §3.4): checkpoints, session_keys, agents and anchors, all in the API schema (L8 §3).
// Memory for tests; Postgres in production. The service connects as the table owner, so RLS doesn't apply.

import type { Pool, PoolClient } from "pg";
import type { Hex } from "viem";

export type CheckpointStatus = "pending" | "validated" | "anchored" | "superseded" | "rejected";

export interface CheckpointRow {
  id: string;
  agentKey: Hex;
  lane: number;
  seqTo: bigint;
  chainRoot: Hex;
  batchEntity: Hex;
  status: CheckpointStatus;
  receivedAt: Date;
}

export interface LeafJson {
  agent_key: Hex;
  lane: number;
  seq_to: string;
  chain_root: Hex;
  /** checkpoints rows this leaf anchors (the leaf's own row first, then older covered ones). */
  ids: string[];
}

/** building → manifest → sent → included → published → safe → finalized; failed needs an operator. */
export type AnchorStatus =
  | "building"
  | "manifest"
  | "sent"
  | "included"
  | "published"
  | "safe"
  | "finalized"
  | "failed";

export interface AnchorRow {
  root: Hex;
  chainId: bigint;
  contract: Hex;
  leaves: LeafJson[];
  status: AnchorStatus;
  manifestKey?: Hex;
  txHash?: Hex;
  rawTx?: Hex;
  epoch?: bigint;
  blockNumber?: bigint;
  blockTime?: Date;
  reason?: string;
  createdAt: Date;
}

export interface AnchoredLeaf {
  ids: string[];
  root: Hex;
  epoch: bigint;
  txHash: Hex;
  proof: Hex[];
  entity: Hex;
}

export interface AnchorDb {
  checkpoints(status: CheckpointStatus, limit: number): Promise<CheckpointRow[]>;
  setCheckpointStatus(ids: string[], status: CheckpointStatus, reason?: string): Promise<void>;
  /** Highest anchored checkpoint for (agent, lane). */
  lastAnchored(agentKey: Hex, lane: number): Promise<{ seqTo: bigint; chainRoot: Hex } | undefined>;
  /** Session keys the recorder announced for this agent and lane (delegation notices). */
  sessionKeys(agentKey: Hex, lane: number): Promise<Hex[]>;
  anchor(root: Hex): Promise<AnchorRow | undefined>;
  /** The one unfinished anchor (building … included), if any. */
  openAnchor(): Promise<AnchorRow | undefined>;
  anchorsIn(statuses: AnchorStatus[]): Promise<AnchorRow[]>;
  lastAnchorAt(): Promise<Date | undefined>;
  insertAnchor(row: AnchorRow): Promise<void>;
  updateAnchor(root: Hex, patch: Partial<AnchorRow>): Promise<void>;
  /** One transaction: leaf rows → anchored (with epoch, tx, proof, entity), covered rows → superseded, anchor → published. */
  markPublished(root: Hex, leaves: AnchoredLeaf[]): Promise<void>;
}

const OPEN: AnchorStatus[] = ["building", "manifest", "sent", "included"];

export class MemoryAnchorDb implements AnchorDb {
  readonly rows = new Map<
    string,
    CheckpointRow & { reason?: string; epoch?: bigint; proof?: Hex[]; entity?: Hex }
  >();
  readonly anchors = new Map<Hex, AnchorRow>();
  readonly keys = new Map<string, Hex[]>();
  #n = 0;

  addCheckpoint(
    c: Omit<CheckpointRow, "id" | "status" | "receivedAt"> & { receivedAt?: Date },
  ): string {
    const dup = [...this.rows.values()].find(
      (r) => r.agentKey === c.agentKey && r.lane === c.lane && r.seqTo === c.seqTo,
    );
    if (dup) return dup.id;
    const id = `c${++this.#n}`;
    this.rows.set(id, { receivedAt: new Date(), ...c, id, status: "pending" });
    return id;
  }
  addSessionKey(agentKey: Hex, lane: number, key: Hex) {
    const k = `${agentKey}:${lane}`;
    this.keys.set(k, [...(this.keys.get(k) ?? []), key.toLowerCase() as Hex]);
  }

  async checkpoints(status: CheckpointStatus, limit: number) {
    return [...this.rows.values()]
      .filter((r) => r.status === status)
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }
  async setCheckpointStatus(ids: string[], status: CheckpointStatus, reason?: string) {
    for (const id of ids) {
      const r = this.rows.get(id);
      if (r) Object.assign(r, { status, ...(reason ? { reason } : {}) });
    }
  }
  async lastAnchored(agentKey: Hex, lane: number) {
    let best: CheckpointRow | undefined;
    for (const r of this.rows.values())
      if (
        r.status === "anchored" &&
        r.agentKey === agentKey &&
        r.lane === lane &&
        (!best || r.seqTo > best.seqTo)
      )
        best = r;
    return best && { seqTo: best.seqTo, chainRoot: best.chainRoot };
  }
  async sessionKeys(agentKey: Hex, lane: number) {
    return this.keys.get(`${agentKey}:${lane}`) ?? [];
  }
  async anchor(root: Hex) {
    const a = this.anchors.get(root);
    return a && structuredClone(a);
  }
  async openAnchor() {
    const a = [...this.anchors.values()].find((x) => OPEN.includes(x.status));
    return a && structuredClone(a);
  }
  async anchorsIn(statuses: AnchorStatus[]) {
    return [...this.anchors.values()]
      .filter((a) => statuses.includes(a.status))
      .map((a) => structuredClone(a));
  }
  async lastAnchorAt() {
    const sent = [...this.anchors.values()]
      .filter((a) => a.status !== "failed")
      .map((a) => a.createdAt.getTime());
    return sent.length ? new Date(Math.max(...sent)) : undefined;
  }
  async insertAnchor(row: AnchorRow) {
    if (this.anchors.has(row.root)) throw new Error("duplicate root");
    this.anchors.set(row.root, structuredClone(row));
  }
  async updateAnchor(root: Hex, patch: Partial<AnchorRow>) {
    Object.assign(this.anchors.get(root) as AnchorRow, structuredClone(patch));
  }
  async markPublished(root: Hex, leaves: AnchoredLeaf[]) {
    for (const l of leaves) {
      const [own, ...covered] = l.ids;
      Object.assign(this.rows.get(own as string) as object, {
        status: "anchored",
        epoch: l.epoch,
        proof: l.proof,
        entity: l.entity,
      });
      await this.setCheckpointStatus(covered, "superseded");
    }
    await this.updateAnchor(root, { status: "published" });
  }
}

const hex = (b: Buffer | null | undefined) => (b ? (`0x${b.toString("hex")}` as Hex) : undefined);
const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");

/** Postgres: the API's `checkpoints`/`session_keys`/`agents` plus `anchors` (API migration v4). */
export class PgAnchorDb implements AnchorDb {
  readonly pool: Pool;
  constructor(pool: Pool) {
    this.pool = pool;
  }

  async checkpoints(status: CheckpointStatus, limit: number) {
    const { rows } = await this.pool.query(
      `SELECT c.id, a.agent_key, c.lane, c.seq_to::text, c.chain_root, c.batch_entity, c.status, c.received_at
         FROM checkpoints c JOIN agents a ON a.id = c.agent_id
        WHERE c.status = $1 ORDER BY c.received_at LIMIT $2`,
      [status, limit],
    );
    return rows.map((r) => ({
      id: r.id as string,
      agentKey: hex(r.agent_key) as Hex,
      lane: r.lane as number,
      seqTo: BigInt(r.seq_to),
      chainRoot: hex(r.chain_root) as Hex,
      batchEntity: hex(r.batch_entity) as Hex,
      status: r.status as CheckpointStatus,
      receivedAt: r.received_at as Date,
    }));
  }
  async setCheckpointStatus(ids: string[], status: CheckpointStatus, reason?: string) {
    if (!ids.length) return;
    await this.pool.query(
      "UPDATE checkpoints SET status = $2, reject_reason = COALESCE($3, reject_reason) WHERE id = ANY($1::uuid[])",
      [ids, status, reason ?? null],
    );
  }
  async lastAnchored(agentKey: Hex, lane: number) {
    const { rows } = await this.pool.query(
      `SELECT c.seq_to::text, c.chain_root FROM checkpoints c JOIN agents a ON a.id = c.agent_id
        WHERE a.agent_key = $1 AND c.lane = $2 AND c.status = 'anchored' ORDER BY c.seq_to DESC LIMIT 1`,
      [buf(agentKey), lane],
    );
    const r = rows[0];
    return r && { seqTo: BigInt(r.seq_to), chainRoot: hex(r.chain_root) as Hex };
  }
  async sessionKeys(agentKey: Hex, lane: number) {
    const { rows } = await this.pool.query(
      `SELECT s.address FROM session_keys s JOIN agents a ON a.id = s.agent_id
        WHERE a.agent_key = $1 AND s.lane = $2 AND s.revoked_at IS NULL`,
      [buf(agentKey), lane],
    );
    return rows.map((r) => hex(r.address) as Hex);
  }
  #anchor(r: Record<string, unknown>): AnchorRow {
    return {
      root: hex(r.root as Buffer) as Hex,
      chainId: BigInt(r.chain_id as string),
      contract: hex(r.contract as Buffer) as Hex,
      leaves: r.leaves as LeafJson[],
      status: r.status as AnchorStatus,
      createdAt: r.created_at as Date,
      ...(r.manifest_key ? { manifestKey: hex(r.manifest_key as Buffer) as Hex } : {}),
      ...(r.tx_hash ? { txHash: hex(r.tx_hash as Buffer) as Hex } : {}),
      ...(r.raw_tx ? { rawTx: hex(r.raw_tx as Buffer) as Hex } : {}),
      ...(r.epoch != null ? { epoch: BigInt(r.epoch as string) } : {}),
      ...(r.block_number != null ? { blockNumber: BigInt(r.block_number as string) } : {}),
      ...(r.block_time ? { blockTime: r.block_time as Date } : {}),
      ...(r.reason ? { reason: r.reason as string } : {}),
    };
  }
  async anchor(root: Hex) {
    const { rows } = await this.pool.query("SELECT * FROM anchors WHERE root = $1", [buf(root)]);
    return rows[0] && this.#anchor(rows[0]);
  }
  async openAnchor() {
    const { rows } = await this.pool.query(
      "SELECT * FROM anchors WHERE status = ANY($1) ORDER BY created_at LIMIT 1",
      [OPEN],
    );
    return rows[0] && this.#anchor(rows[0]);
  }
  async anchorsIn(statuses: AnchorStatus[]) {
    const { rows } = await this.pool.query(
      "SELECT * FROM anchors WHERE status = ANY($1) ORDER BY created_at",
      [statuses],
    );
    return rows.map((r) => this.#anchor(r));
  }
  async lastAnchorAt() {
    const { rows } = await this.pool.query(
      "SELECT max(created_at) AS at FROM anchors WHERE status <> 'failed'",
    );
    return (rows[0]?.at as Date | null) ?? undefined;
  }
  async insertAnchor(a: AnchorRow) {
    await this.pool.query(
      `INSERT INTO anchors (root, chain_id, contract, leaves, leaf_count, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        buf(a.root),
        a.chainId.toString(),
        buf(a.contract),
        JSON.stringify(a.leaves),
        a.leaves.length,
        a.status,
        a.createdAt,
      ],
    );
  }
  async updateAnchor(root: Hex, p: Partial<AnchorRow>, q: Pool | PoolClient = this.pool) {
    const cols: [string, unknown][] = [];
    if (p.status) cols.push(["status", p.status]);
    if (p.manifestKey) cols.push(["manifest_key", buf(p.manifestKey)]);
    if (p.txHash) cols.push(["tx_hash", buf(p.txHash)]);
    if (p.rawTx) cols.push(["raw_tx", buf(p.rawTx)]);
    if (p.epoch !== undefined) cols.push(["epoch", p.epoch.toString()]);
    if (p.blockNumber !== undefined) cols.push(["block_number", p.blockNumber.toString()]);
    if (p.blockTime) cols.push(["block_time", p.blockTime]);
    if (p.reason) cols.push(["reason", p.reason]);
    if (!cols.length) return;
    await q.query(
      `UPDATE anchors SET ${cols.map(([c], i) => `${c} = $${i + 2}`).join(", ")} WHERE root = $1`,
      [buf(root), ...cols.map(([, v]) => v)],
    );
  }
  async markPublished(root: Hex, leaves: AnchoredLeaf[]) {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      for (const l of leaves) {
        const [own, ...covered] = l.ids;
        await c.query(
          `UPDATE checkpoints SET status = 'anchored', anchor_epoch = $2, anchor_tx = $3, anchor_root = $4,
             proof = $5, checkpoint_entity = $6, anchored_at = now() WHERE id = $1`,
          [own, l.epoch.toString(), buf(l.txHash), buf(l.root), l.proof.map(buf), buf(l.entity)],
        );
        if (covered.length)
          await c.query(
            `UPDATE checkpoints SET status = 'superseded', anchor_epoch = $2, anchor_tx = $3, anchored_at = now()
              WHERE id = ANY($1::uuid[])`,
            [covered, l.epoch.toString(), buf(l.txHash)],
          );
      }
      await this.updateAnchor(root, { status: "published" }, c);
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
}
