// EIP-712 statements (L1 §7) [NORMATIVE].
import { type Hex, hashTypedData, recoverTypedDataAddress } from "viem";
import { EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION } from "./constants.js";

export const EIP712_TYPES = {
  Delegation: [
    { name: "agentKey", type: "bytes32" },
    { name: "lane", type: "uint32" },
    { name: "sessionKey", type: "address" },
    { name: "notBefore", type: "uint64" },
    { name: "notAfter", type: "uint64" },
    { name: "scope", type: "uint32" },
    { name: "recorder", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
  Revocation: [
    { name: "agentKey", type: "bytes32" },
    { name: "sessionKey", type: "address" },
    { name: "effectiveAt", type: "uint64" },
    { name: "reason", type: "string" },
  ],
  AgentProfile: [
    { name: "agentKey", type: "bytes32" },
    { name: "privacyLevel", type: "uint8" },
    { name: "retentionDays", type: "uint32" },
    { name: "watchedHash", type: "bytes32" },
    { name: "readersHash", type: "bytes32" },
    { name: "version", type: "uint64" },
  ],
  ReaderKey: [
    { name: "owner", type: "address" },
    { name: "x25519", type: "bytes32" },
    { name: "label", type: "string" },
    { name: "notAfter", type: "uint64" },
  ],
  KeyGrant: [
    { name: "agentKey", type: "bytes32" },
    { name: "epochId", type: "uint32" },
    { name: "kekId", type: "bytes32" },
    { name: "reader", type: "bytes32" },
    { name: "encHash", type: "bytes32" },
  ],
  Approval: [
    { name: "agentKey", type: "bytes32" },
    { name: "lane", type: "uint32" },
    { name: "requestSeq", type: "uint64" },
    { name: "requestHash", type: "bytes32" },
    { name: "decision", type: "uint8" },
    { name: "expiresAt", type: "uint64" },
  ],
  ApprovalAttestation: [
    { name: "agentKey", type: "bytes32" },
    { name: "lane", type: "uint32" },
    { name: "requestSeq", type: "uint64" },
    { name: "requestHash", type: "bytes32" },
    { name: "decision", type: "uint8" },
    { name: "approver", type: "string" },
    { name: "attestedAt", type: "uint64" },
  ],
  Attestation: [
    { name: "agentKey", type: "bytes32" },
    { name: "lane", type: "uint32" },
    { name: "seqTo", type: "uint64" },
    { name: "chainRoot", type: "bytes32" },
    { name: "verdict", type: "uint8" },
    { name: "findingsHash", type: "bytes32" },
    { name: "scope", type: "string" },
  ],
  CheckpointStatement: [
    { name: "agentKey", type: "bytes32" },
    { name: "lane", type: "uint32" },
    { name: "seqTo", type: "uint64" },
    { name: "chainRoot", type: "bytes32" },
    { name: "anchorRoot", type: "bytes32" },
    { name: "anchorChainId", type: "uint64" },
    { name: "anchorTx", type: "bytes32" },
  ],
} as const;

export type StatementType = keyof typeof EIP712_TYPES;

/** Delegation.scope bitmask (L1 §7). */
export const DELEGATION_SCOPE = {
  RECORDS: 1,
  TX_INTENTS: 2,
  KEYGRANTS: 4,
  SUB_DELEGATE: 8,
} as const;

export function eip712Domain(chainId: number | bigint) {
  return {
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId: BigInt(chainId),
  } as const;
}

/** Full typed-data payload, e.g. for wallet `signTypedData`. */
export function typedData<T extends StatementType>(
  chainId: number | bigint,
  primaryType: T,
  message: Record<string, unknown>,
) {
  return { domain: eip712Domain(chainId), types: EIP712_TYPES, primaryType, message };
}

export function hashTyped<T extends StatementType>(
  chainId: number | bigint,
  primaryType: T,
  message: Record<string, unknown>,
): Hex {
  return hashTypedData(typedData(chainId, primaryType, message) as never);
}

export async function verifyTyped<T extends StatementType>(
  chainId: number | bigint,
  primaryType: T,
  message: Record<string, unknown>,
  sig: Hex,
  expected: Hex,
): Promise<boolean> {
  try {
    const addr = await recoverTypedDataAddress({
      ...typedData(chainId, primaryType, message),
      signature: sig,
    } as never);
    return addr.toLowerCase() === expected.toLowerCase();
  } catch {
    return false;
  }
}
