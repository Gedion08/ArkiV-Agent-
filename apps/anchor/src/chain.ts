// RecorderAnchor on Base (L5 §2). The tx is signed locally and its raw bytes + hash are journaled before
// broadcast, so a restart rebroadcasts the same bytes and never signs a second anchor for one root (A5).
import { AfrError } from "@afr/core";
import {
  type Account,
  type Chain,
  encodeFunctionData,
  type Hex,
  keccak256,
  type PublicClient,
  parseAbi,
  parseEventLogs,
  parseTransaction,
} from "viem";

export const RECORDER_ANCHOR_ABI = parseAbi([
  "function anchorRoot(bytes32 root, uint32 leafCount, bytes32 manifestKey) returns (uint64)",
  "function epochOf(bytes32 root) view returns (uint64)",
  "function rootOf(uint64 epoch) view returns (bytes32)",
  "function isRecorder(address) view returns (bool)",
  "function verify(uint64 e, bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot, bytes32[] proof) view returns (bool)",
  "event Anchored(uint64 indexed epoch, bytes32 indexed root, uint32 leafCount, bytes32 manifestKey, address indexed recorder)",
  "error NotRecorder()",
  "error DuplicateRoot()",
  "error ZeroRoot()",
  "error EmptyAnchor()",
]);

/** shortcut: a viem local account; the KMS account (L5 §3.3) plugs in here with the same interface. */
export type AnchorSigner = Account & {
  signTransaction: NonNullable<Account["signTransaction"]>;
  signTypedData: NonNullable<Account["signTypedData"]>;
};

export interface AnchorChainOptions {
  publicClient: PublicClient;
  chain: Chain;
  contract: Hex;
  signer: AnchorSigner;
}

export interface Inclusion {
  epoch: bigint;
  blockNumber: bigint;
  blockTime: Date;
}

export class AnchorChain {
  readonly o: AnchorChainOptions;
  constructor(o: AnchorChainOptions) {
    this.o = o;
  }

  get chainId(): bigint {
    return BigInt(this.o.chain.id);
  }

  async epochOf(root: Hex): Promise<bigint> {
    return this.o.publicClient.readContract({
      address: this.o.contract,
      abi: RECORDER_ANCHOR_ABI,
      functionName: "epochOf",
      args: [root],
    });
  }

  /** Signs (not sends) anchorRoot with a fresh pending nonce. Reverts (NotRecorder, DuplicateRoot) surface here. */
  async sign(root: Hex, leafCount: number, manifestKey: Hex): Promise<{ raw: Hex; hash: Hex }> {
    const pc = this.o.publicClient;
    const from = this.o.signer.address;
    const data = encodeFunctionData({
      abi: RECORDER_ANCHOR_ABI,
      functionName: "anchorRoot",
      args: [root, leafCount, manifestKey],
    });
    const [nonce, gas, fees] = await Promise.all([
      pc.getTransactionCount({ address: from, blockTag: "pending" }),
      pc.estimateGas({ account: from, to: this.o.contract, data }),
      pc.estimateFeesPerGas(),
    ]);
    const raw = await this.o.signer.signTransaction({
      chainId: this.o.chain.id,
      type: "eip1559",
      to: this.o.contract,
      data,
      nonce,
      gas: (gas * 3n) / 2n,
      maxFeePerGas: fees.maxFeePerGas,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    });
    return { raw, hash: keccak256(raw) };
  }

  /** Sends the journaled bytes. "Already known"/"nonce too low" mean the node has it or it's mined: fine. */
  async broadcast(raw: Hex): Promise<void> {
    await this.o.publicClient
      .sendRawTransaction({ serializedTransaction: raw })
      .catch((e: unknown) => {
        if (
          !/already known|known transaction|already imported|nonce too low/i.test(
            String((e as Error).message),
          )
        )
          throw e;
      });
  }

  /** Waits up to `timeoutMs` for the receipt; never throws (the next tick looks again). */
  async settle(hash: Hex, timeoutMs: number): Promise<void> {
    await this.o.publicClient
      .waitForTransactionReceipt({ hash, timeout: timeoutMs })
      .catch(() => undefined);
  }

  /**
   * "pending": the node has it. "unknown": the node doesn't (rebroadcast the same bytes).
   * "dropped": unknown and its nonce went to another tx. Throws ANCHOR_REVERTED on a reverted receipt.
   */
  async inclusion(hash: Hex, raw: Hex): Promise<Inclusion | "pending" | "unknown" | "dropped"> {
    const pc = this.o.publicClient;
    const r = await pc.getTransactionReceipt({ hash }).catch(() => undefined);
    if (!r) {
      if (await pc.getTransaction({ hash }).catch(() => undefined)) return "pending";
      const nonce = parseTransaction(raw).nonce ?? 0;
      const used = await pc.getTransactionCount({
        address: this.o.signer.address,
        blockTag: "latest",
      });
      return used > nonce ? "dropped" : "unknown";
    }
    if (r.status !== "success") throw new AfrError("ANCHOR_REVERTED", `anchor tx ${hash} reverted`);
    const [ev] = parseEventLogs({ abi: RECORDER_ANCHOR_ABI, eventName: "Anchored", logs: r.logs });
    if (!ev) throw new AfrError("ANCHOR_REVERTED", "receipt has no Anchored event");
    const block = await pc.getBlock({ blockNumber: r.blockNumber });
    return {
      epoch: ev.args.epoch,
      blockNumber: r.blockNumber,
      blockTime: new Date(Number(block.timestamp) * 1000),
    };
  }

  /** Block numbers of the `safe` and `finalized` tags (L5 §3.1 step 4). */
  async tags(): Promise<{ safe: bigint; finalized: bigint }> {
    const pc = this.o.publicClient;
    const [s, f] = await Promise.all([
      pc.getBlock({ blockTag: "safe" }),
      pc.getBlock({ blockTag: "finalized" }),
    ]);
    return { safe: s.number, finalized: f.number };
  }
}
