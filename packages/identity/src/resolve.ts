// Agent resolution and operator checks against the ERC-8004 IdentityRegistry (L5 §4.3, §4.4).
// operatorAt reads ownerOf at the last block at or before ts (historical eth_call) rather than scanning
// Transfer logs: public RPCs cap eth_getLogs at a few hundred blocks (abis/README.md).
import { AfrError, parseAgentId } from "@afr/core";
import {
  BaseError,
  ContractFunctionRevertedError,
  type Hex,
  hashTypedData,
  type PublicClient,
  parseAbi,
  recoverTypedDataAddress,
  type TypedDataDefinition,
  zeroAddress,
} from "viem";
import { IDENTITY_REGISTRY_ABI } from "./abis/identity.js";
import {
  type AfrService,
  findAfrService,
  parseRegistration,
  type Registration,
} from "./registration.js";
import { type FetchUriOptions, fetchUriJson } from "./uri.js";

export type IdentityClient = Pick<
  PublicClient,
  "getBlock" | "getChainId" | "getCode" | "readContract"
>;

const ERC1271_ABI = parseAbi([
  "function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)",
]);
const ERC1271_MAGIC = "0x1626ba7e";

const reverted = (e: unknown) =>
  e instanceof BaseError && e.walk((x) => x instanceof ContractFunctionRevertedError) !== null;

async function target(agentId: string, rpc: IdentityClient) {
  const { chainId, registry, tokenId } = parseAgentId(agentId);
  if (BigInt(await rpc.getChainId()) !== chainId)
    throw new AfrError("CHAIN_MISMATCH", `rpc is not chain ${chainId}`);
  return { registry, tokenId };
}

/** The last block whose timestamp is ≤ ts (unix seconds). Probes near the target, never from genesis. */
export async function blockAtOrBefore(rpc: IdentityClient, ts: bigint): Promise<bigint> {
  const latest = await rpc.getBlock({ blockTag: "latest" });
  if (ts >= latest.timestamp) return latest.number;
  const stamp = async (n: bigint) => {
    try {
      return (await rpc.getBlock({ blockNumber: n })).timestamp;
    } catch {
      throw new AfrError("RPC_HISTORY_UNAVAILABLE", `rpc has no header for block ${n}`);
    }
  };
  // exponential search back from latest (overshoots ≤ 2× the distance, block times vary), then bisect:
  // ts(lo) ≤ ts < ts(hi)
  let hi = latest.number;
  let step = 1n;
  let lo = -1n; // none found yet
  while (lo < 0n) {
    const n = hi > step ? hi - step : 0n;
    if ((await stamp(n)) <= ts) lo = n;
    else if (n === 0n) throw new AfrError("BEFORE_GENESIS", "ts is before the chain's first block");
    else {
      hi = n;
      step *= 2n;
    }
  }
  while (hi - lo > 1n) {
    const mid: bigint = (lo + hi) / 2n;
    if ((await stamp(mid)) <= ts) lo = mid;
    else hi = mid;
  }
  return lo;
}

async function ownerOf(rpc: IdentityClient, registry: Hex, tokenId: bigint, blockNumber?: bigint) {
  try {
    const o = await rpc.readContract({
      address: registry,
      abi: IDENTITY_REGISTRY_ABI,
      functionName: "ownerOf",
      args: [tokenId],
      ...(blockNumber !== undefined ? { blockNumber } : {}),
    });
    return o.toLowerCase() as Hex;
  } catch (e) {
    if (reverted(e)) throw new AfrError("AGENT_NOT_REGISTERED", "agent has no owner at that block");
    if (blockNumber !== undefined)
      throw new AfrError("RPC_HISTORY_UNAVAILABLE", `rpc can't read state at block ${blockNumber}`);
    throw e;
  }
}

/** The agent NFT's owner at the end of the last block with timestamp ≤ ts (unix seconds). */
export async function operatorAt(agentId: string, ts: bigint, rpc: IdentityClient): Promise<Hex> {
  const { registry, tokenId } = await target(agentId, rpc);
  return ownerOf(rpc, registry, tokenId, await blockAtOrBefore(rpc, ts));
}

export interface ResolvedAgent {
  owner: Hex;
  uri: string;
  registration: Registration;
  afr?: AfrService;
  agentWallet?: Hex;
}

/** Current owner, agent URI and registration file (with its afr entry), and the verified agentWallet. */
export async function resolveAgent(
  agentId: string,
  rpc: IdentityClient,
  opts: FetchUriOptions = {},
): Promise<ResolvedAgent> {
  const { registry, tokenId } = await target(agentId, rpc);
  const owner = await ownerOf(rpc, registry, tokenId);
  const uri = await rpc.readContract({
    address: registry,
    abi: IDENTITY_REGISTRY_ABI,
    functionName: "tokenURI",
    args: [tokenId],
  });
  const registration = parseRegistration(await fetchUriJson(uri, opts));
  const afr = findAfrService(registration);
  const wallet = await rpc
    .readContract({
      address: registry,
      abi: IDENTITY_REGISTRY_ABI,
      functionName: "getAgentWallet",
      args: [tokenId],
    })
    .catch(() => zeroAddress); // older drafts have no getAgentWallet
  return {
    owner,
    uri,
    registration,
    ...(afr ? { afr } : {}),
    ...(wallet !== zeroAddress ? { agentWallet: wallet.toLowerCase() as Hex } : {}),
  };
}

export interface OperatorSigResult {
  ok: boolean;
  method: "ecdsa" | "erc1271";
  operator: Hex;
  note?: string;
}

/**
 * Was `sig` over `typedData` made by the agent's operator at ts? ECDSA first; if the operator is a contract
 * (a Safe), ERC-1271 `isValidSignature` at the current block (most RPCs can't answer for the past).
 */
export async function verifyOperatorSig(
  agentId: string,
  typedData: TypedDataDefinition,
  sig: Hex,
  ts: bigint,
  rpc: IdentityClient,
): Promise<OperatorSigResult> {
  const operator = await operatorAt(agentId, ts, rpc);
  const signer = await recoverTypedDataAddress({ ...typedData, signature: sig }).catch(
    () => undefined,
  );
  if (signer?.toLowerCase() === operator) return { ok: true, method: "ecdsa", operator };
  const code = await rpc.getCode({ address: operator });
  if (!code || code === "0x") return { ok: false, method: "ecdsa", operator };
  const magic = await rpc
    .readContract({
      address: operator,
      abi: ERC1271_ABI,
      functionName: "isValidSignature",
      args: [hashTypedData(typedData), sig],
    })
    .catch(() => undefined);
  return {
    ok: magic === ERC1271_MAGIC,
    method: "erc1271",
    operator,
    note: "ERC-1271 checked at the current block, not at ts",
  };
}
