// Chain root and batch digest (L1 §5.2–5.3) [NORMATIVE].
import { encodeAbiParameters, encodePacked, type Hex, keccak256 } from "viem";
import { DOMAIN } from "./constants.js";

/** chain_root_n = keccak256(abi.encodePacked("AFR_CHAIN_V1", prev, batch_root, uint64 seq_to)). */
export function chainRoot(prev: Hex, batchRootHex: Hex, seqTo: bigint): Hex {
  return keccak256(
    encodePacked(
      ["string", "bytes32", "bytes32", "uint64"],
      [DOMAIN.CHAIN, prev, batchRootHex, seqTo],
    ),
  );
}

export interface BatchDigestInput {
  agentKey: Hex;
  lane: number;
  seqFrom: bigint;
  seqTo: bigint;
  batchRoot: Hex;
  prevChainRoot: Hex;
  chainRoot: Hex;
  payloadCtHash: Hex;
}

export function batchDigest(p: BatchDigestInput): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "uint64" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        DOMAIN.BATCH,
        p.agentKey,
        p.lane,
        p.seqFrom,
        p.seqTo,
        p.batchRoot,
        p.prevChainRoot,
        p.chainRoot,
        p.payloadCtHash,
      ],
    ),
  );
}
