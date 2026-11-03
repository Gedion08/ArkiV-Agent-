import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { encodePacked, keccak256 } from "viem";
import { describe, expect, test } from "vitest";
import {
  batchDigest,
  batchProof,
  batchRoot,
  chainRoot,
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
