// Arkiv chain + clients factory (Rabdi now; localhost/mainnet later). Reads retry on transient
// HTTP failures (SPIKES S8); viem never retries eth_sendRawTransaction.
import { createPublicClient, type PublicArkivClient } from "@arkiv-network/sdk";
import { rabdi } from "@arkiv-network/sdk/chains";
import { type Chain, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { PrivacyLevel } from "../privacy.js";
import { ArkivStore } from "./store.js";
import { type WriteJournal, WriterQueue } from "./writer-queue.js";

export function arkivPublicClient(accessKey: string): {
  chain: Chain;
  publicClient: PublicArkivClient;
} {
  const chain = rabdi({ accessKey });
  const publicClient = createPublicClient({
    chain,
    transport: http(undefined, { timeout: 30_000, retryCount: 3, retryDelay: 500 }),
  });
  return { chain, publicClient };
}

export interface ArkivStoreConfig {
  accessKey: string;
  /** 0x-prefixed 32-byte hex, read from the env var named in config (never logged). */
  writerKey: string;
  journal: WriteJournal;
  spendCapWei: bigint;
  privacyLevel?: PrivacyLevel;
}

export function createArkivStore(c: ArkivStoreConfig) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(c.writerKey)) throw new Error("writer key is not 32-byte hex");
  const { chain, publicClient } = arkivPublicClient(c.accessKey);
  const queue = new WriterQueue({
    publicClient: publicClient as never,
    account: privateKeyToAccount(c.writerKey as `0x${string}`),
    chain,
    journal: c.journal,
    spendCapWei: c.spendCapWei,
  });
  return new ArkivStore({
    queue,
    publicClient,
    ...(c.privacyLevel !== undefined ? { privacyLevel: c.privacyLevel } : {}),
  });
}
