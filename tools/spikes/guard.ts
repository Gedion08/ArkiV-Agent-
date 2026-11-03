// Guarded spike writer (Arkiv write-safety rules, modelled on the quickstart's guardedWalletClient +
// localEnvSigner). Every eth_sendTransaction the SDK makes is intercepted here:
//   gas = max(1_000_000 + 400_000·(N−1), 2·estimate@latest), gas ≤ head.gasLimit/2, else stop;
//   fresh nonce (latest) + current gasPrice, legacy tx; spend cap + balance checked before signing;
//   tx hash fsync'd to the journal BEFORE broadcast; never retried or resent.
// Never logs the key, signed bytes, raw provider errors or the keyed RPC URL.
import { closeSync, fsyncSync, openSync, writeSync } from "node:fs";
import { createWalletClient } from "@arkiv-network/sdk";
import {
  custom,
  decodeErrorResult,
  decodeFunctionData,
  formatEther,
  type Hex,
  keccak256,
  parseAbi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chain, json, publicClient } from "./env.ts";

export const REGISTRY = "0x4400000000000000000000000000000000000044";
const EXECUTE = parseAbi([
  "function execute((uint8 operation, bytes operationData)[] ops) external returns (bytes32[] keys)",
]);
const ENGINE_ERRORS = parseAbi([
  "error EmptyBatch()",
  "error EntityNotFound(bytes32 entityKey)",
  "error EntityExpired(bytes32 entityKey, uint64 expiresAt)",
  "error NotOwner(bytes32 entityKey, address caller, address owner)",
  "error ReadOnlyEntity(bytes32 entityKey)",
  "error ReservedCreationFlags(uint8 creationFlags)",
  "error ExpiryDeadOnArrival(uint64 target, uint64 currentBlock)",
  "error ExpiryBeyondMaxLifetime(uint64 target, uint64 currentBlock, uint64 maxLifetime)",
  "error ExpiryNotExtended(bytes32 entityKey, uint64 newExpiresAt, uint64 currentExpiresAt)",
  "error TransferToZeroAddress(bytes32 entityKey)",
  "error TransferToSelf(bytes32 entityKey)",
]);

/** eth_call at latest (Rabdi's eth_estimateGas drops revert data); returns the engine error name. */
export async function engineCall(from: Hex, data: Hex): Promise<string> {
  try {
    await publicClient.call({ account: from, to: REGISTRY, data, blockTag: "latest" });
    return "ok";
  } catch (e) {
    let c = e as { data?: Hex; cause?: unknown };
    while (c && !c.data && c.cause) c = c.cause as typeof c;
    if (!c?.data) return "reverted, no data";
    try {
      return decodeErrorResult({ abi: ENGINE_ERRORS, data: c.data }).errorName;
    } catch {
      return `reverted ${c.data.slice(0, 10)}`;
    }
  }
}

const READS = new Set([
  "eth_blockNumber",
  "eth_chainId",
  "eth_getTransactionReceipt",
  "eth_getTransactionByHash",
  "eth_getBlockByNumber",
  "eth_call",
  "eth_estimateGas",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_gasPrice",
]);
const JOURNAL = new URL("./journal.ndjson", import.meta.url);

function journal(entry: Record<string, unknown>) {
  const fd = openSync(JOURNAL, "a");
  try {
    writeSync(fd, `${json({ at: new Date().toISOString(), ...entry })}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Error class + first line, with URLs (which carry the access key) stripped. */
export function sanitize(e: unknown) {
  const err = e as Error;
  const line = (err.message ?? "").split("\n")[0]?.replace(/\b(?:https?|wss?):\/\/\S+/g, "<url>");
  const status = (e as { status?: number }).status;
  return `${err.name}${status ? ` [HTTP ${status}]` : ""}: ${line?.slice(0, 240)}`;
}

/**
 * Simulation-only wallet acting as `from` (no key needed): the SDK estimates the batch, which
 * surfaces engine reverts; if estimation passes, the send is refused. Nothing is signed.
 */
export function dryWallet(from: Hex) {
  const transport = custom({
    request: async ({ method, params }) => {
      if (method === "eth_estimateGas" || method === "eth_sendTransaction") {
        const r = await engineCall(from, (params as [{ data: Hex }])[0].data);
        throw new Error(`guard: dry-run ${r === "ok" ? "eth_call ok (would succeed)" : r}`);
      }
      if (READS.has(method)) return publicClient.request({ method, params } as never);
      throw new Error(`guard: method ${method} refused`);
    },
  });
  const wallet = createWalletClient({ chain, account: from, transport });
  return async (fn: (w: typeof wallet) => Promise<unknown>) => {
    try {
      await fn(wallet);
      return "unexpected: sent";
    } catch (e) {
      let c = e as { message?: string; cause?: unknown } | undefined;
      while (c && !c.message?.includes("guard: dry-run") && c.cause) c = c.cause as typeof c;
      const m = c?.message?.includes("guard: dry-run") ? c.message : sanitize(e);
      return m.match(/guard: dry-run ([^\n]*)/)?.[1] ?? `refused before call: ${m}`;
    }
  };
}

export interface Sent {
  label: string;
  hash: Hex;
  ops: number;
  gas: bigint;
  gasPrice: bigint;
  estimate: bigint;
  calldataBytes: number;
}

/** A wallet client whose sends go through the guard, with a hard cumulative spend cap. */
export function guardedWallet(keyEnv: string, spendCapWei: bigint) {
  const pk = process.env[keyEnv];
  if (!pk || !/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error(`${keyEnv} missing or malformed`);
  const signer = privateKeyToAccount(pk as Hex);
  const address = signer.address;
  let reserved = 0n;
  let label = "unlabelled";
  const sent: Sent[] = [];

  const transport = custom({
    request: async ({ method, params }) => {
      if (READS.has(method)) return publicClient.request({ method, params } as never);
      if (method !== "eth_sendTransaction") throw new Error(`guard: method ${method} refused`);
      const input = (params as [{ from: string; to: string; data: Hex }])[0];
      if (
        input.from.toLowerCase() !== address.toLowerCase() ||
        input.to?.toLowerCase() !== REGISTRY
      )
        throw new Error("guard: unexpected from/to");
      const { args } = decodeFunctionData({ abi: EXECUTE, data: input.data });
      const n = BigInt(args[0].length);
      const call = { account: address, to: REGISTRY, data: input.data } as const;
      const estimate = await publicClient.estimateGas({ ...call, blockTag: "latest" }).catch(() => {
        throw new Error("guard: gas estimation failed; not signing");
      });
      const floor = 1_000_000n + 400_000n * (n - 1n);
      const gas = estimate * 2n > floor ? estimate * 2n : floor;
      const head = await publicClient.getBlock({ blockTag: "latest" });
      if (gas * 2n > head.gasLimit) throw new Error(`guard: gas ${gas} > half block limit`);
      const [nonce, gasPrice, balance] = await Promise.all([
        publicClient.getTransactionCount({ address, blockTag: "latest" }),
        publicClient.getGasPrice(),
        publicClient.getBalance({ address, blockTag: "latest" }),
      ]);
      const max = gas * gasPrice;
      if (reserved + max > spendCapWei) throw new Error("guard: spend cap reached; not signing");
      if (balance < max) throw new Error("guard: balance too low; not signing");
      reserved += max;
      const signed = await signer.signTransaction({
        chainId: chain.id,
        type: "legacy",
        to: REGISTRY,
        data: input.data,
        value: 0n,
        gas,
        gasPrice,
        nonce,
      });
      const hash = keccak256(signed);
      const calldataBytes = (input.data.length - 2) / 2;
      journal({
        label,
        phase: "signed",
        hash,
        from: address,
        nonce,
        ops: Number(n),
        gas,
        gasPrice,
        estimate,
        calldataBytes,
        txBytes: (signed.length - 2) / 2,
      });
      const got = await publicClient
        .sendRawTransaction({ serializedTransaction: signed })
        .catch(() => {
          journal({ label, phase: "submission_uncertain", hash });
          throw new Error(`guard: submission uncertain for ${hash}; reconcile, do not resend`);
        });
      if (got.toLowerCase() !== hash.toLowerCase())
        throw new Error("guard: RPC returned a different hash");
      sent.push({ label, hash, ops: Number(n), gas, gasPrice, estimate, calldataBytes });
      return hash;
    },
  });

  const wallet = createWalletClient({ chain, account: address, transport, pollingInterval: 1000 });

  return {
    address,
    wallet,
    sent,
    /** Explicit gas so the SDK skips its own estimate; the guard sets the real gas/nonce/price. */
    tx: { gas: 1_000_000n },
    /** Run one labelled write; checks receipt status, reports actual cost, never retries. */
    async run<T extends { txHash: Hex }>(l: string, fn: () => Promise<T>) {
      label = l;
      const before = sent.length;
      try {
        const out = await fn();
        const r = await publicClient.getTransactionReceipt({ hash: out.txHash });
        if (r.status !== "success") throw new Error(`receipt ${r.status}`);
        const cost = r.gasUsed * r.effectiveGasPrice;
        journal({
          label: l,
          phase: "receipt",
          hash: out.txHash,
          status: r.status,
          gasUsed: r.gasUsed,
          cost,
        });
        const s = sent[before];
        return {
          out,
          gasUsed: r.gasUsed,
          cost,
          costGlm: formatEther(cost),
          gas: s?.gas,
          estimate: s?.estimate,
          calldataBytes: s?.calldataBytes,
        };
      } catch (e) {
        const h = sent[before]?.hash;
        if (h) journal({ label: l, phase: "failed", hash: h, error: (e as Error).name });
        throw new Error(`${l} failed: ${sanitize(e)}${h ? ` tx ${h}` : ""}`);
      }
    },
  };
}
