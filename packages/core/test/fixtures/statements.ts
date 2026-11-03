import type { StatementType } from "../../src/index.js";
import { H32 } from "./headers.js";

/** One sample message per EIP-712 statement type (bigints for uint64+, numbers for ≤ uint32). */
export const STATEMENTS: { [K in StatementType]: Record<string, unknown> } = {
  Delegation: {
    agentKey: H32("01"),
    lane: 0,
    sessionKey: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    notBefore: 1793577600n,
    notAfter: 1793664000n,
    scope: 1,
    recorder: "afr-recorder/0.0.0",
    nonce: 123456789n,
  },
  Revocation: {
    agentKey: H32("01"),
    sessionKey: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    effectiveAt: 1793600000n,
    reason: "key compromise",
  },
  AgentProfile: {
    agentKey: H32("01"),
    privacyLevel: 1,
    retentionDays: 365,
    watchedHash: H32("02"),
    readersHash: H32("03"),
    version: 1n,
  },
  ReaderKey: {
    owner: "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
    x25519: H32("04"),
    label: "auditor",
    notAfter: 1825113600n,
  },
  KeyGrant: {
    agentKey: H32("01"),
    epochId: 352,
    kekId: H32("05"),
    reader: H32("04"),
    encHash: H32("06"),
  },
  Approval: {
    agentKey: H32("01"),
    lane: 0,
    requestSeq: 7n,
    requestHash: H32("07"),
    decision: 1,
    expiresAt: 1793581200n,
  },
  ApprovalAttestation: {
    agentKey: H32("01"),
    lane: 0,
    requestSeq: 7n,
    requestHash: H32("07"),
    decision: 2,
    approver: "slack:T123/U456",
    attestedAt: 1793578000n,
  },
  Attestation: {
    agentKey: H32("01"),
    lane: 0,
    seqTo: 99n,
    chainRoot: H32("08"),
    verdict: 1,
    findingsHash: H32("09"),
    scope: "Q4-2026 sample",
  },
  CheckpointStatement: {
    agentKey: H32("01"),
    lane: 0,
    seqTo: 99n,
    chainRoot: H32("08"),
    anchorRoot: H32("0a"),
    anchorChainId: 84532n,
    anchorTx: H32("0b"),
  },
};
