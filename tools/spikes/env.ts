// Shared spike setup: loads .env by name only (values are never printed), Rabdi public client.
import { createPublicClient } from "@arkiv-network/sdk";
import { rabdi } from "@arkiv-network/sdk/chains";
import { http } from "viem";

process.loadEnvFile(new URL("../../.env", import.meta.url));
const accessKey = process.env.ARKIV_ACCESS_KEY;
if (!accessKey) throw new Error("ARKIV_ACCESS_KEY missing from .env");
export const chain = rabdi({ accessKey });
/** Non-200 HTTP statuses seen (S8 evidence: 429 = rate limited). */
export const httpStatuses: Record<number, number> = {};
// Reads retry on transient HTTP failures; viem never retries eth_sendRawTransaction.
export const publicClient = createPublicClient({
  chain,
  transport: http(undefined, {
    timeout: 30_000,
    retryCount: 3,
    retryDelay: 500,
    onFetchResponse: (r) => {
      if (r.status !== 200) httpStatuses[r.status] = (httpStatuses[r.status] ?? 0) + 1;
    },
  }),
});
export const json = (v: unknown) =>
  JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
