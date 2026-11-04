// Injected readers for verifyAgent (L7 §1): identity and anchor chains are trusted for chain data,
// Arkiv is not (it's the EvidenceStore, and everything read from it is checked).
import { AfrError } from "@afr/core";
import {
  type AfrService,
  type IdentityClient,
  resolveAgent,
  verifyOperatorSig,
} from "@afr/identity";
import {
  type Hex,
  type PublicClient,
  parseAbi,
  parseEventLogs,
  recoverTypedDataAddress,
  type TypedDataDefinition,
} from "viem";

export interface IdentityReader {
  /** The agent's registration; throws AfrError AGENT_NOT_REGISTERED for an unknown agent. */
  resolve(agentId: string): Promise<{ afr?: AfrService }>;
  /** Was `typedData` signed by the agent's operator as of `ts` (unix seconds)? */
  isOperatorSig(
    agentId: string,
    typedData: TypedDataDefinition,
    sig: Hex,
    ts: bigint,
  ): Promise<boolean>;
}

export interface AnchorReader {
  /** rootOf(epoch) (zero when unknown) and, when `tx` emitted that Anchored event, its block time. */
  anchor(
    chainId: bigint,
    contract: Hex,
    epoch: bigint,
    tx: Hex,
  ): Promise<{ root: Hex; blockTime?: bigint }>;
  isRecorder(chainId: bigint, contract: Hex, address: Hex): Promise<boolean>;
}

/** ERC-8004 on the identity chain (ECDSA, or ERC-1271 for contract operators). */
export function rpcIdentityReader(rpc: IdentityClient): IdentityReader {
  return {
    resolve: (agentId) => resolveAgent(agentId, rpc),
    isOperatorSig: async (agentId, typedData, sig, ts) => {
      try {
        return (await verifyOperatorSig(agentId, typedData, sig, ts, rpc)).ok;
      } catch (e) {
        if ((e as AfrError).code === "AGENT_NOT_REGISTERED") return false; // not yet minted at ts
        throw e;
      }
    },
  };
}

/** `local:` dev agents (no registry): a fixed operator address, ECDSA only. */
export function staticIdentityReader(operator: Hex, afr?: AfrService): IdentityReader {
  return {
    resolve: async () => (afr ? { afr } : {}),
    isOperatorSig: async (_agentId, typedData, sig) => {
      const signer = await recoverTypedDataAddress({ ...typedData, signature: sig }).catch(
        () => undefined,
      );
      return signer?.toLowerCase() === operator.toLowerCase();
    },
  };
}

const RECORDER_ANCHOR_ABI = parseAbi([
  "function rootOf(uint64 epoch) view returns (bytes32)",
  "function isRecorder(address) view returns (bool)",
  "event Anchored(uint64 indexed epoch, bytes32 indexed root, uint32 leafCount, bytes32 manifestKey, address indexed recorder)",
]);

/** RecorderAnchor over viem public clients, keyed by anchor chain id. */
export function rpcAnchorReader(clients: Record<string, PublicClient>): AnchorReader {
  const client = (chainId: bigint) => {
    const c = clients[chainId.toString()];
    if (!c) throw new AfrError("NO_ANCHOR_RPC", `no RPC for anchor chain ${chainId}`);
    return c;
  };
  return {
    async anchor(chainId, contract, epoch, tx) {
      const c = client(chainId);
      const root = (await c.readContract({
        address: contract,
        abi: RECORDER_ANCHOR_ABI,
        functionName: "rootOf",
        args: [epoch],
      })) as Hex;
      const receipt = await c.getTransactionReceipt({ hash: tx }).catch(() => undefined);
      const emitted =
        receipt &&
        parseEventLogs({ abi: RECORDER_ANCHOR_ABI, logs: receipt.logs }).some(
          (l) =>
            l.address.toLowerCase() === contract.toLowerCase() &&
            l.args.epoch === epoch &&
            l.args.root === root,
        );
      if (!receipt || !emitted) return { root };
      return {
        root,
        blockTime: (await c.getBlock({ blockNumber: receipt.blockNumber })).timestamp,
      };
    },
    isRecorder: (chainId, contract, address) =>
      client(chainId).readContract({
        address: contract,
        abi: RECORDER_ANCHOR_ABI,
        functionName: "isRecorder",
        args: [address],
      }) as Promise<boolean>,
  };
}
