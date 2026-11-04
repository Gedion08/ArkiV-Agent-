// Batch Merkle tree (L1 §5.1) and anchor tree (L1 §6) [NORMATIVE].
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import type { Hex } from "viem";
import { AfrError } from "./errors.js";

export interface BatchEntry {
  seq: bigint;
  hash: Hex;
}

const BATCH_LEAF = ["uint64", "bytes32"];

function batchTree(entries: readonly BatchEntry[]) {
  if (entries.length === 0) throw new AfrError("BATCH_EMPTY", "batches are never empty");
  for (let i = 1; i < entries.length; i++) {
    if ((entries[i] as BatchEntry).seq <= (entries[i - 1] as BatchEntry).seq) {
      throw new AfrError("BATCH_ORDER", "batch entries must be strictly ascending by seq");
    }
  }
  return StandardMerkleTree.of(
    entries.map((e) => [e.seq, e.hash]),
    BATCH_LEAF,
  );
}

export function batchRoot(entries: readonly BatchEntry[]): Hex {
  return batchTree(entries).root as Hex;
}

/** Proof for the entry with `seq`. Looked up by leaf value, never by index (L1 §13). */
export function batchProof(entries: readonly BatchEntry[], seq: bigint): Hex[] {
  const e = entries.find((x) => x.seq === seq);
  if (!e) throw new AfrError("BATCH_SEQ_NOT_FOUND", "seq not in batch");
  return batchTree(entries).getProof([e.seq, e.hash]) as Hex[];
}

export function verifyBatchProof(root: Hex, entry: BatchEntry, proof: readonly Hex[]): boolean {
  return StandardMerkleTree.verify(root, BATCH_LEAF, [entry.seq, entry.hash], [...proof]);
}

export interface AnchorLeaf {
  agentKey: Hex;
  lane: number;
  seqTo: bigint;
  chainRoot: Hex;
}

const ANCHOR_LEAF = ["bytes32", "uint32", "uint64", "bytes32"];

const anchorValue = (l: AnchorLeaf) => [l.agentKey.toLowerCase(), l.lane, l.seqTo, l.chainRoot];

/** Leaves sorted by (agent_key, lane), one per (agent, lane): the same set always gives the same tree. */
export function sortAnchorLeaves(leaves: readonly AnchorLeaf[]): AnchorLeaf[] {
  if (leaves.length === 0) throw new AfrError("ANCHOR_EMPTY", "anchors are never empty");
  const sorted = [...leaves].sort((a, b) => {
    const ka = a.agentKey.toLowerCase();
    const kb = b.agentKey.toLowerCase();
    return ka < kb ? -1 : ka > kb ? 1 : a.lane - b.lane;
  });
  for (let i = 1; i < sorted.length; i++) {
    const a = sorted[i - 1] as AnchorLeaf;
    const b = sorted[i] as AnchorLeaf;
    if (a.agentKey.toLowerCase() === b.agentKey.toLowerCase() && a.lane === b.lane)
      throw new AfrError("ANCHOR_DUPLICATE", "one leaf per (agent, lane) per anchor");
  }
  return sorted;
}

function anchorTree(leaves: readonly AnchorLeaf[]) {
  return StandardMerkleTree.of(sortAnchorLeaves(leaves).map(anchorValue), ANCHOR_LEAF);
}

export function anchorRoot(leaves: readonly AnchorLeaf[]): Hex {
  return anchorTree(leaves).root as Hex;
}

/** Proof for the (agent, lane) leaf. Looked up by leaf value, never by index (L1 §13). */
export function anchorProof(leaves: readonly AnchorLeaf[], agentKey: Hex, lane: number): Hex[] {
  const l = leaves.find(
    (x) => x.agentKey.toLowerCase() === agentKey.toLowerCase() && x.lane === lane,
  );
  if (!l) throw new AfrError("ANCHOR_LEAF_NOT_FOUND", "(agent, lane) not in anchor");
  return anchorTree(leaves).getProof(anchorValue(l)) as Hex[];
}

export function verifyAnchorProof(root: Hex, leaf: AnchorLeaf, proof: readonly Hex[]): boolean {
  return StandardMerkleTree.verify(root, ANCHOR_LEAF, anchorValue(leaf), [...proof]);
}
