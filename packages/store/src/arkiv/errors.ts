// Map Arkiv engine reverts and SDK errors to StoreError codes. Rabdi's eth_estimateGas drops revert
// data (SPIKES S9), so reverts are decoded from an eth_call at latest. Messages never carry raw
// provider text (it can include the keyed RPC URL).
import { AfrError } from "@afr/core";
import { decodeErrorResult, type Hex, type PublicClient, parseAbi } from "viem";
import type { StoreErrorCode } from "../types.js";

export const REGISTRY = "0x4400000000000000000000000000000000000044" as const;

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

const CODES: Record<string, StoreErrorCode> = {
  NotOwner: "NOT_OWNER",
  ReadOnlyEntity: "READONLY",
  ExpiryNotExtended: "EXPIRY_NOT_EXTENDED",
  EntityNotFound: "NOT_FOUND",
  EntityExpired: "NOT_FOUND",
  ExpiryBeyondMaxLifetime: "EXPIRY_INVALID",
  ExpiryDeadOnArrival: "EXPIRY_INVALID",
};

/** eth_call the registry at latest: "ok", or the decoded engine error name. */
export async function engineCall(client: PublicClient, from: Hex, data: Hex): Promise<string> {
  try {
    await client.call({ account: from, to: REGISTRY, data, blockTag: "latest" });
    return "ok";
  } catch (e) {
    let c = e as { data?: Hex; cause?: unknown } | undefined;
    while (c && !c.data && c.cause) c = c.cause as typeof c;
    if (!c?.data) return "unknown";
    try {
      return decodeErrorResult({ abi: ENGINE_ERRORS, data: c.data }).errorName;
    } catch {
      return "unknown";
    }
  }
}

export const engineError = (name: string) =>
  new AfrError(CODES[name] ?? "REVERTED", `Arkiv engine rejected the operation (${name})`);

/** First AfrError in a cause chain (the SDK wraps transport errors), else a sanitized REVERTED/TIMEOUT. */
export function toStoreError(e: unknown): AfrError {
  for (let c = e as { cause?: unknown } | undefined; c; c = c.cause as typeof c)
    if (c instanceof AfrError) return c;
  const name = (e as Error)?.name ?? "Error";
  if (name === "InvalidExpiryError")
    return new AfrError("EXPIRY_INVALID", "expiry beyond Arkiv MAX_LIFETIME");
  if (name === "WaitForTransactionReceiptTimeoutError")
    return new AfrError("TIMEOUT", "receipt timeout");
  const status = (e as { status?: number }).status;
  if (status === 429) return new AfrError("RATE_LIMITED", "HTTP 429");
  return new AfrError("REVERTED", `Arkiv write failed (${name})`);
}
