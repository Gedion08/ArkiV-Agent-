// L3 §7 WriterQueue: one per writer account, one tx in flight, Arkiv write-safety rules.
// The SDK builds calldata; a custom EIP-1193 transport intercepts eth_sendTransaction (SPIKES S4):
//   gas = max(1_000_000 + 400_000·(N−1), 2·estimate@latest), ≤ latest.gasLimit / 2, else stop;
//   fresh nonce (latest) + current gasPrice, legacy; balance + spend cap checked before signing;
//   signed bytes + hash journaled durably BEFORE broadcast; never re-signed.
import { AfrError } from "@afr/core";
import { createWalletClient, type WalletArkivClient } from "@arkiv-network/sdk";
import {
  type Chain,
  custom,
  decodeFunctionData,
  type Hex,
  keccak256,
  type LocalAccount,
  type PublicClient,
  parseAbi,
} from "viem";
import { engineCall, engineError, REGISTRY, toStoreError } from "./errors.js";

const EXECUTE = parseAbi([
  "function execute((uint8 operation, bytes operationData)[] ops) external returns (bytes32[] keys)",
]);
const READS = new Set([
  "eth_blockNumber",
  "eth_chainId",
  "eth_getTransactionReceipt",
  "eth_getTransactionByHash",
  "eth_getBlockByNumber",
  "eth_call",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_gasPrice",
]);

export type WriteState = "intent" | "submitting" | "receipt_confirmed" | "verified" | "failed";

export interface WriteEntry {
  id: Hex;
  state: WriteState;
  predictedKey?: Hex;
  txHash?: Hex;
  nonce?: number;
  /** Signed tx bytes (public once broadcast); kept only to rebroadcast the same bytes. */
  signed?: Hex;
  reason?: string;
}

/** Durable intent journal. `set` must be durable (fsync'd) before it resolves. */
export interface WriteJournal {
  get(id: Hex): Promise<WriteEntry | undefined>;
  set(entry: WriteEntry): Promise<void>;
}

/** shortcut: not durable, for tests; the recorder passes its SQLite journal (P2-10). */
export class MemoryWriteJournal implements WriteJournal {
  readonly entries = new Map<Hex, WriteEntry>();
  async get(id: Hex) {
    const e = this.entries.get(id);
    return e && { ...e };
  }
  async set(entry: WriteEntry) {
    this.entries.set(entry.id, { ...entry });
  }
}

export interface WriterQueueOptions {
  publicClient: PublicClient;
  account: LocalAccount;
  chain: Chain;
  journal: WriteJournal;
  /** Hard cap on Σ(gas × gasPrice) reserved by this queue. */
  spendCapWei: bigint;
  receiptTimeoutMs?: number;
}

export type QueueReconcile =
  | { state: "confirmed" }
  | { state: "reverted"; reason: string }
  | { state: "uncertain" }
  | { state: "not_sent" };

export class WriterQueue {
  readonly wallet: WalletArkivClient;
  readonly address: Hex;
  #tail: Promise<unknown> = Promise.resolve();
  #current: WriteEntry | undefined;
  #reserved = 0n;

  readonly o: WriterQueueOptions;

  constructor(o: WriterQueueOptions) {
    this.o = o;
    this.address = o.account.address;
    const transport = custom(
      {
        request: async ({ method, params }) => {
          if (READS.has(method)) return o.publicClient.request({ method, params } as never);
          if (method !== "eth_sendTransaction")
            throw new AfrError("REVERTED", `method ${method} not allowed`);
          return this.#signAndSend((params as [{ from: Hex; to: Hex; data: Hex }])[0]);
        },
      },
      { retryCount: 0 },
    ); // a retried eth_sendTransaction would re-sign
    this.wallet = createWalletClient({
      chain: o.chain,
      account: this.address,
      transport,
      pollingInterval: 1000,
    });
  }

  /** Explicit gas makes the SDK skip its own estimate; the interceptor sets the real values. */
  static readonly TX = { gas: 1_000_000n } as const;

  /** Run one write op for journal entry `id`, strictly one at a time. */
  run<T>(id: Hex, op: (wallet: WalletArkivClient, entry: WriteEntry) => Promise<T>): Promise<T> {
    const next = this.#tail.then(async () => {
      const entry: WriteEntry = (await this.o.journal.get(id)) ?? { id, state: "intent" };
      if (entry.state !== "intent" && entry.state !== "failed")
        throw new AfrError(
          "IDEMPOTENCY_CONFLICT",
          `write already ${entry.state}; reconcile, never re-sign`,
        );
      if (entry.state === "failed" && entry.txHash)
        throw new AfrError(
          "IDEMPOTENCY_CONFLICT",
          "write reverted on-chain; re-prepare under a new id",
        );
      const fresh: WriteEntry = {
        id,
        state: "intent",
        ...(entry.predictedKey ? { predictedKey: entry.predictedKey } : {}),
      };
      await this.o.journal.set(fresh);
      this.#current = fresh;
      try {
        const out = await op(this.wallet, fresh);
        if (fresh.txHash) await this.o.journal.set({ ...fresh, state: "receipt_confirmed" });
        return out;
      } catch (e) {
        // Before signing: no broadcast evidence → failed. After: stay "submitting" unless the receipt
        // proves a revert.
        if (!fresh.txHash)
          await this.o.journal.set({ ...fresh, state: "failed", reason: toStoreError(e).code });
        else if (await this.#provenReverted(fresh.txHash))
          await this.o.journal.set({ ...fresh, state: "failed", reason: "REVERTED" });
        throw toStoreError(e);
      } finally {
        this.#current = undefined;
      }
    });
    this.#tail = next.catch(() => {});
    return next;
  }

  async #provenReverted(hash: Hex) {
    const r = await this.o.publicClient.getTransactionReceipt({ hash }).catch(() => undefined);
    return r?.status === "reverted";
  }

  async #signAndSend(input: { from: Hex; to: Hex; data: Hex }): Promise<Hex> {
    const entry = this.#current;
    if (!entry) throw new AfrError("REVERTED", "send outside a queued write");
    if (entry.txHash)
      throw new AfrError("IDEMPOTENCY_CONFLICT", "already signed in this run; never re-sign");
    const pc = this.o.publicClient;
    if (
      input.from.toLowerCase() !== this.address.toLowerCase() ||
      input.to?.toLowerCase() !== REGISTRY
    )
      throw new AfrError("REVERTED", "unexpected from/to");
    const { args } = decodeFunctionData({ abi: EXECUTE, data: input.data });
    const n = BigInt(args[0].length);
    const call = { account: this.address, to: REGISTRY, data: input.data } as const;
    const estimate = await pc.estimateGas({ ...call, blockTag: "latest" }).catch(async () => {
      throw engineError(await engineCall(pc, this.address, input.data));
    });
    const floor = 1_000_000n + 400_000n * (n - 1n);
    const gas = estimate * 2n > floor ? estimate * 2n : floor;
    const head = await pc.getBlock({ blockTag: "latest" });
    if (gas * 2n > head.gasLimit)
      throw new AfrError(
        "PAYLOAD_TOO_LARGE",
        `gas ${gas} exceeds half the block gas limit; split the write`,
      );
    const [nonce, gasPrice, balance] = await Promise.all([
      pc.getTransactionCount({ address: this.address, blockTag: "latest" }),
      pc.getGasPrice(),
      pc.getBalance({ address: this.address, blockTag: "latest" }),
    ]);
    const max = gas * gasPrice;
    if (this.#reserved + max > this.o.spendCapWei)
      throw new AfrError("REVERTED", "spend cap reached; not signing");
    if (balance < max) throw new AfrError("REVERTED", "writer balance too low; not signing");
    const signed = await this.o.account.signTransaction({
      chainId: this.o.chain.id,
      type: "legacy",
      to: REGISTRY,
      data: input.data,
      value: 0n,
      gas,
      gasPrice,
      nonce,
    });
    const txHash = keccak256(signed);
    this.#reserved += max;
    Object.assign(entry, { state: "submitting", txHash, nonce, signed });
    await this.o.journal.set(entry); // durable before broadcast
    return this.#broadcast(signed, txHash);
  }

  async #broadcast(signed: Hex, txHash: Hex) {
    const got = await this.o.publicClient
      .sendRawTransaction({ serializedTransaction: signed })
      .catch(() => {
        throw new AfrError("LOST_RESPONSE", `submission uncertain for ${txHash}; reconcile`);
      });
    if (got.toLowerCase() !== txHash.toLowerCase())
      throw new AfrError("LOST_RESPONSE", "RPC returned a different hash");
    return txHash;
  }

  /**
   * L3 §7 restart path for a `submitting` entry: receipt by hash; if the node doesn't know it and the
   * nonce is unconsumed, rebroadcast the SAME signed bytes (same hash, can't double-apply); if the
   * nonce was consumed by another tx → uncertain (ops).
   */
  async reconcile(id: Hex): Promise<QueueReconcile> {
    const e = await this.o.journal.get(id);
    if (!e || e.state === "intent") return { state: "not_sent" };
    if (e.state === "failed")
      return e.txHash
        ? { state: "reverted", reason: e.reason ?? "REVERTED" }
        : { state: "not_sent" };
    if (e.state !== "submitting") return { state: "confirmed" };
    const pc = this.o.publicClient;
    const hash = e.txHash as Hex;
    let receipt = await pc.getTransactionReceipt({ hash }).catch(() => undefined);
    if (!receipt) {
      const latest = await pc.getTransactionCount({ address: this.address, blockTag: "latest" });
      if (latest > (e.nonce as number)) return { state: "uncertain" };
      await this.#broadcast(e.signed as Hex, hash).catch(() => undefined);
      receipt = await pc
        .waitForTransactionReceipt({ hash, timeout: this.o.receiptTimeoutMs ?? 60_000 })
        .catch(() => undefined);
      if (!receipt) return { state: "uncertain" };
    }
    if (receipt.status !== "success") {
      await this.o.journal.set({ ...e, state: "failed", reason: "REVERTED" });
      return { state: "reverted", reason: "REVERTED" };
    }
    await this.o.journal.set({ ...e, state: "receipt_confirmed" });
    return { state: "confirmed" };
  }
}
