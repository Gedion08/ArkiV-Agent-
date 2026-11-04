import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { encodePacked, type Hex, keccak256 } from "viem";
import { describe, expect, test } from "vitest";
import {
  type AnchorLeaf,
  anchorProof,
  anchorProofs,
  anchorRoot,
  batchDigest,
  batchProof,
  batchRoot,
  chainRoot,
  sortAnchorLeaves,
  verifyAnchorProof,
  verifyBatchProof,
  ZERO_HASH,
} from "../src/index.js";
import { H32 } from "./fixtures/headers.js";

const entries = [0n, 1n, 2n, 3n, 4n].map((seq, i) => ({ seq, hash: H32(`0${i + 1}`) }));

describe("T5 batch merkle", () => {
  test("every leaf's proof verifies; forged leaves fail", () => {
    const root = batchRoot(entries);
    for (const e of entries) {
      const proof = batchProof(entries, e.seq);
      expect(verifyBatchProof(root, e, proof)).toBe(true);
      expect(verifyBatchProof(root, { seq: e.seq + 10n, hash: e.hash }, proof)).toBe(false);
      expect(verifyBatchProof(root, { seq: e.seq, hash: H32("ff") }, proof)).toBe(false);
    }
  });

  test("root equals OZ StandardMerkleTree with [uint64, bytes32]", () => {
    const oz = StandardMerkleTree.of(
      entries.map((e) => [e.seq, e.hash]),
      ["uint64", "bytes32"],
    );
    expect(batchRoot(entries)).toBe(oz.root);
  });

  test("single-record batch works; empty and unordered batches throw", () => {
    expect(
      verifyBatchProof(batchRoot([entries[0]!]), entries[0]!, batchProof([entries[0]!], 0n)),
    ).toBe(true);
    expect(() => batchRoot([])).toThrow(expect.objectContaining({ code: "BATCH_EMPTY" }));
    expect(() => batchRoot([entries[1]!, entries[0]!])).toThrow(
      expect.objectContaining({ code: "BATCH_ORDER" }),
    );
  });
});

describe("chain", () => {
  test("chainRoot = keccak(encodePacked(AFR_CHAIN_V1, prev, root, uint64))", () => {
    const r = batchRoot(entries);
    expect(chainRoot(ZERO_HASH, r, 4n)).toBe(
      keccak256(
        encodePacked(
          ["string", "bytes32", "bytes32", "uint64"],
          ["AFR_CHAIN_V1", ZERO_HASH, r, 4n],
        ),
      ),
    );
    expect(chainRoot(ZERO_HASH, r, 4n)).not.toBe(chainRoot(ZERO_HASH, r, 5n));
  });

  test("batchDigest binds every field", () => {
    const p = {
      agentKey: H32("01"),
      lane: 0,
      seqFrom: 0n,
      seqTo: 4n,
      batchRoot: H32("02"),
      prevChainRoot: ZERO_HASH,
      chainRoot: H32("03"),
      payloadCtHash: H32("04"),
    };
    const d = batchDigest(p);
    for (const [k, v] of Object.entries({
      lane: 1,
      seqFrom: 1n,
      seqTo: 5n,
      payloadCtHash: H32("05"),
    })) {
      expect(batchDigest({ ...p, [k]: v })).not.toBe(d);
    }
  });
});

describe("P3-01 anchor merkle (L1 §6)", () => {
  const leaves: AnchorLeaf[] = [
    { agentKey: H32("bb"), lane: 0, seqTo: 9n, chainRoot: H32("01") },
    { agentKey: H32("aa"), lane: 2, seqTo: 3n, chainRoot: H32("02") },
    { agentKey: H32("aa"), lane: 1, seqTo: 7n, chainRoot: H32("03") },
  ];

  test("root equals OZ StandardMerkleTree over the (agent_key, lane)-sorted leaves", () => {
    const sorted = [leaves[2]!, leaves[1]!, leaves[0]!];
    const oz = StandardMerkleTree.of(
      sorted.map((l) => [l.agentKey, l.lane, l.seqTo, l.chainRoot]),
      ["bytes32", "uint32", "uint64", "bytes32"],
    );
    expect(sortAnchorLeaves(leaves)).toEqual(sorted);
    expect(anchorRoot(leaves)).toBe(oz.root);
    expect(anchorRoot([...leaves].reverse())).toBe(oz.root); // input order never matters
  });

  test("anchorProofs equals anchorProof per leaf, in sorted order", () => {
    expect(anchorProofs(leaves)).toEqual(
      sortAnchorLeaves(leaves).map((l) => anchorProof(leaves, l.agentKey, l.lane)),
    );
  });

  test("every proof verifies; a forged seq_to, chain_root or lane fails", () => {
    const root = anchorRoot(leaves);
    for (const l of leaves) {
      const proof = anchorProof(leaves, l.agentKey, l.lane);
      expect(verifyAnchorProof(root, l, proof)).toBe(true);
      expect(verifyAnchorProof(root, { ...l, seqTo: l.seqTo + 1n }, proof)).toBe(false);
      expect(verifyAnchorProof(root, { ...l, chainRoot: H32("ff") }, proof)).toBe(false);
      expect(verifyAnchorProof(root, { ...l, lane: l.lane + 5 }, proof)).toBe(false);
    }
  });

  test("empty, duplicate (agent, lane) and unknown leaves throw", () => {
    expect(() => anchorRoot([])).toThrow(expect.objectContaining({ code: "ANCHOR_EMPTY" }));
    const dup = {
      ...leaves[0]!,
      agentKey: leaves[0]!.agentKey.toUpperCase().replace("0X", "0x") as Hex,
      seqTo: 1n,
    };
    expect(() => anchorRoot([...leaves, dup])).toThrow(
      expect.objectContaining({ code: "ANCHOR_DUPLICATE" }),
    );
    expect(() => anchorProof(leaves, H32("cc"), 0)).toThrow(
      expect.objectContaining({ code: "ANCHOR_LEAF_NOT_FOUND" }),
    );
  });
});
