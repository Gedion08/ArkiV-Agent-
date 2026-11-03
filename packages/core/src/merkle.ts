// Batch Merkle tree (L1 §5.1) [NORMATIVE]. Anchor trees (L1 §6) arrive in P3.
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
