# L1 — Record Format & Crypto Core (`@afr/core`)

> **Format v1-rc (frozen 2026-11-05, ADR-025).** The record, batch, delegation, checkpoint and anchor formats, domain strings, EIP-712 types and constants in this doc are frozen. From here on, any change to them needs an ADR in `docs/01-architecture/ADRS.md` and regenerated `packages/test-vectors`. Editorial fixes that change no bytes or behaviour don't.

> **[NORMATIVE]** This layer defines the evidence format. Recorder, verifier, dashboard, watcher and any third-party implementation MUST match it byte for byte. Once v1 ships, changes to hashed structures require a version bump (`v: 2`).

| | |
|---|---|
| Package | `packages/core` → `@afr/core` |
| Depends on | `viem` (types, abi encoding, signing utils), `@noble/hashes`, `@noble/curves`, `canonicalize`, `@openzeppelin/merkle-tree` |
| Depended on by | everything |
| Requirements covered | INT-01…INT-08, VER-06 |
| Phase | P1 (types, JCS, hash, sign, chain), P2 (batch digest), P3 (anchor leaves) |

---

## 1. Responsibilities

- TypeScript types + Zod schemas for every record, statement and frame.
- Canonicalisation (JCS) and hashing.
- Commitments (salted hashes).
- Session-key signing/verification (EIP-191).
- EIP-712 typed data definitions + hash/verify helpers.
- Merkle trees (batch, anchor) and proofs.
- Chain-root and batch-digest computation.
- Agent ID parsing and `agent_key`.
- Constants registry ([Architecture §21](../01-architecture/ARCHITECTURE.md#21-constants-registry-normative)).
- Golden test vectors (`packages/test-vectors`).

**Not responsible for:** encryption (L4), storage (L3), I/O of any kind. `@afr/core` is **pure**: no network, no filesystem, no clock (time is passed in), no randomness (salts are passed in, or produced by an injected RNG).

---

## 2. Identifiers

### 2.1 Agent ID

```
agent_id  = "eip155:" <chainId:decimal> ":" <registry:0x-lowercase-40hex> ":" <tokenId:decimal>
agent_key = keccak256(utf8(agent_id))          // bytes32
```

Example: `eip155:8453:0x1234abcd…ef:42`.

- `parseAgentId(s)` validates it strictly: no leading zeros in decimals, lowercase hex, 40 hex chars.
- Agents without ERC-8004 identity (dev mode only) use `local:<uuid-v4>`. The verifier labels them "unanchored identity".

### 2.2 Other IDs

| ID | Format |
|---|---|
| `lane` | uint32. 0 for MVP |
| `seq` | uint64, starts at 0 per (agent, lane), +1 per record |
| `session_id` | 16 random bytes hex (`0x…32`), one per recorder session (= per session key) |
| `batch_id` | `keccak256(abi.encode(agent_key, lane, seq_from))` |
| `epoch_id` | uint32 = `month*16 + rotation`, where `month` = months since 2025-01 (UTC) and `rotation` ∈ 0..15 (0 unless rotated early). The sub-index is always present so ids never collide across months: 2026-11 → 22·16 = **352** |
| `record_hash` | bytes32 |

---

## 3. Action record [NORMATIVE]

A record has a **header** (hashed and signed) and a **body** (plaintext, committed to by the header, encrypted at rest).

### 3.1 Header

```ts
type Hex = `0x${string}`;          // lowercase
type U64 = string;                  // decimal string (JCS-safe)

interface RecordHeaderV1 {
  v: 1;
  agent_id: string;                 // §2.1
  lane: number;                     // uint32
  seq: U64;
  session_id: Hex;                  // 16 bytes
  ts: U64;                          // recorder clock, ms since epoch (informative)
  type: ActionType;
  prev_hash: Hex;                   // bytes32; 0x00…00 for seq 0
  ref_seq?: U64;                    // for tool_result / tx_broadcast / approval → the originating record
  model?: ModelInfo;                // model_call; optional on tool_call when known
  tool?: ToolInfo;                  // tool_call / tool_result
  tx?: TxInfo;                      // tx_sign / tx_broadcast
  policy?: PolicyInfo;              // when a policy evaluated this action
  approval?: ApprovalInfo;          // approval
  commit: Commitments;              // salted commitments to body parts (may be {})
  meta?: Record<string, string>;    // small, non-sensitive, string-only (≤ 16 keys, ≤ 128 B each)
}

type ActionType =
  | "session_start" | "session_end"
  | "model_call"
  | "tool_call" | "tool_result"
  | "tx_sign" | "tx_broadcast"
  | "msg_sign"                      // EIP-191/EIP-712 signatures by agent wallets (permits, Permit2, off-chain orders)
  | "approval_request" | "approval"
  | "policy_block"
  | "gap"
  | "note";                         // operator annotation (e.g. "incident declared")

interface ModelInfo {
  provider: string;                 // "anthropic" | "openai" | "google" | "local" | …
  id: string;                       // e.g. "claude-opus-5-5"
  version?: string;                 // provider-reported model version/snapshot if available
  params_hash?: Hex;                // keccak(JCS({temperature, max_tokens, tools...}))
  tokens_in?: U64; tokens_out?: U64;
}

interface ToolInfo {
  server: string;                   // MCP server name (from config) or "sdk"
  name: string;                     // tool name
  is_error?: boolean;               // tool_result only (MCP isError or thrown)
  duration_ms?: U64;                // tool_result only
}

interface TxInfo {
  chain_id: U64;
  from: Hex;                        // 20-byte lowercase
  to?: Hex;                         // absent for contract creation
  nonce: U64;
  value: U64;                       // wei, decimal string
  data_commit: Hex;                 // commitment (afr/calldata) — NOT raw calldata
  selector?: Hex;                   // 4 bytes; omitted at privacy 0
  tx_hash?: Hex;                    // known at sign time for raw-signed txs
  kind?: "eoa" | "userop" | "safe";
  user_op_hash?: Hex;
  status?: "sent" | "rejected" | "error";   // tx_broadcast only
  value_usd_cents?: U64;            // if a price was available at record time
}

interface PolicyInfo {
  policy_hash: Hex;                 // keccak(JCS(policy document))
  decision: "allow" | "warn" | "require_approval" | "deny" | "violated";
  rule_id?: string;
  mode: "enforce" | "warn_only";
}

interface ApprovalInfo {
  request_seq: U64;
  decision: "approved" | "rejected" | "expired";
  method: "attested" | "eip712";
  approver: string;                 // address (eip712) or "slack:T123/U456" (attested)
  sig: Hex;                         // EIP-712 signature by approver, or ApprovalAttestation sig by approvals service
  attestor?: Hex;                   // approvals service address (attested only)
}

interface Commitments {
  args?: Hex; result?: Hex; context?: Hex; output?: Hex; calldata?: Hex;
}
```

**Per-type required fields:**

| type | required | notes |
|---|---|---|
| `session_start` | `meta.recorder_version`, `meta.config_hash`, `meta.delegation_hash`, `meta.session_key` | `meta.recovered_from_seq` if restart |
| `session_end` | – | `meta.reason` |
| `model_call` | `model`, `commit.context`, `commit.output` | |
| `tool_call` | `tool`, `commit.args` | `policy` if guardrails on |
| `tool_result` | `tool`, `ref_seq`, `commit.result` | |
| `tx_sign` | `tx` (with `tx_hash` when known), `commit.calldata` | `policy` if guardrails on |
| `tx_broadcast` | `tx.tx_hash`, `tx.status`, `ref_seq` | |
| `msg_sign` | `meta.signer`, `meta.kind` (`personal`/`typed`), `commit.args` (the message/typed data) | `meta.primary_type` + `meta.verifying_contract` for typed data, so permits are recognisable at privacy ≥ 1 |
| `approval_request` | `ref_seq`, `policy` | |
| `approval` | `approval`, `ref_seq` | |
| `policy_block` | `policy`, `ref_seq` | the blocked attempt's own record is the `ref_seq` |
| `gap` | `meta.from_seq`, `meta.to_seq`, `meta.reason` | seqs reserved but not recorded (disk full, crash) |
| `note` | `commit.args` | |

### 3.2 Body

```ts
interface RecordBodyV1 {
  salt: Hex;                        // 32 random bytes, unique per record
  args?: unknown;                   // tool args / tx request (JSON)
  result?: unknown;                 // tool result content (JSON, MCP CallToolResult)
  context?: unknown;                // model input (messages, system, tools) or context capture
  output?: unknown;                 // model output
  calldata?: Hex;                   // raw tx calldata
  truncated?: { field: string; original_hash: Hex; original_bytes: number }[];
  redacted?: { field: string; path: string; reason: string }[];
}
```

### 3.3 Commitments [NORMATIVE]

```
commit(domain, value, salt) =
  keccak256( 0x01 ‖ salt[32] ‖ utf8(domain) ‖ 0x00 ‖ utf8(JCS(value)) )
```

- `domain` ∈ `COMMIT_DOMAIN` (`afr/args`, `afr/result`, `afr/context`, `afr/output`, `afr/calldata`).
- For `calldata`, `value` is the hex string (so JCS(value) = `"0x…"` with quotes).
- **Truncation:** if a body part exceeds `MAX_BODY_BYTES` (default 64 KiB), the commitment is still computed over the **full original** value. The body stores a truncated version plus `truncated[]` with `original_hash = keccak256(utf8(JCS(full)))`. Full verification then reports "commitment not checkable: truncated" for that field. That counts as a warning, not a failure.
- **Redaction:** redaction happens **before** commitment (the committed value is the redacted one). This is listed in `redacted[]`. Secrets never enter the commitment, so they can't be brute-forced.

### 3.4 Record hash and signature [NORMATIVE]

```
record_hash = keccak256( utf8( JCS(header) ) )
sig         = EIP-191 personal_sign by session key over the 32 raw bytes of record_hash
            = secp256k1_sign( keccak256("\x19Ethereum Signed Message:\n32" ‖ record_hash) )
            → 65 bytes r‖s‖v (v ∈ {27,28})
```

With viem: `account.signMessage({ message: { raw: recordHash } })`. Verify with `recoverMessageAddress({ message: { raw }, signature })`.

### 3.5 JCS rules [NORMATIVE]

- RFC 8785 via the `canonicalize` package, applied after the guards below. Its output is the exact bytes hashed.
- Two modes. `jcs()` (strict) is for AFR-defined structures: headers, statements, policy documents. `jcsData()` is for captured data inside commitments (tool args/results, model I/O, which legitimately contain floats and `null`). It uses plain RFC 8785 number serialisation and allows `null`, but still rejects NaN/±Infinity, `undefined`, `bigint` and non-plain objects.
- Strings with lone UTF-16 surrogates are rejected (they have no UTF-8 encoding).
- Allowed JSON number values in hashed objects: only **integers** in [0, 2^31) for small fields (`v`, `lane`). Everything else that is numeric is a **decimal string** (`U64`).
- No `undefined`. Optional fields are **omitted**, never `null`.
- Hex is always lowercase with a `0x` prefix. Addresses are lowercase (not checksummed) inside records.
- Strings **and object keys** are NFC-normalised before canonicalisation (`s.normalize("NFC")`). Keys that collide after normalisation are rejected. Note: this deliberately deviates from plain RFC 8785 for non-NFC input (e.g. U+FB33 becomes U+05D3 U+05BC and sorts differently); `vectors/jcs.json` pins the behaviour.
- `meta` values are strings only.
- Zod schemas enforce all of this (`RecordHeaderV1Schema.strict()`). `buildHeader()` never emits invalid headers.

---

## 4. Hash chain [NORMATIVE]

```
header[0].prev_hash = 0x00…00 (32 zero bytes)
header[n].prev_hash = record_hash[n-1]           // same (agent, lane)
header[n].seq       = header[n-1].seq + 1
```

The chain spans session-key rotations. The first record of a new session is a `session_start`, and its `prev_hash` is the last record of the previous session.

---

## 5. Batches [NORMATIVE]

### 5.1 Batch root

```
leaves      = [ (seq_i: uint64, record_hash_i: bytes32) for each record in batch, ascending seq ]
batch_root  = StandardMerkleTree.of(leaves, ["uint64","bytes32"]).root
```

Batches are never empty. A heartbeat batch carries exactly one `note` record with `meta.event = "heartbeat"`, so every batch consumes at least one seq. That keeps keyset pagination and gap checks simple.

### 5.2 Chain root

```
chain_root_0      = 0x00…00
chain_root_n      = keccak256( abi.encodePacked( "AFR_CHAIN_V1", chain_root_{n-1}, batch_root_n, uint64(seq_to_n) ) )
```

Heartbeat batches also advance the chain root. Liveness is part of the evidence.

### 5.3 Batch digest (what the session key signs)

```
batch_digest = keccak256( abi.encode(
    string  "AFR_BATCH_V1",
    bytes32 agent_key,
    uint32  lane,
    uint64  seq_from,
    uint64  seq_to,
    bytes32 batch_root,
    bytes32 prev_chain_root,
    bytes32 chain_root,
    bytes32 payload_ct_hash      // keccak256 of the encrypted section bytes (L4)
))
batch_sig = EIP-191 sign(batch_digest) by any key in session_keys (ADR-024): preferably the key that
            signed the batch's last record; after a crash, the recorder's current session key (then listed
            in session_keys even if it signed no record of this batch)
```

The batch sig binds the public metadata to the ciphertext, so nobody can swap the payload under a valid root.

### 5.4 Batch public section (inside the frame, unencrypted)

```ts
interface BatchPublicV1 {
  v: 1;
  agent_id: string;
  lane: number;
  seq_from: U64; seq_to: U64;
  prev_chain_root: Hex; chain_root: Hex; batch_root: Hex;
  session_keys: Hex[];                 // distinct record signers, in first-appearance order, + the batch signer if it signed no record (ADR-024)
  records: { seq: U64; hash: Hex; sig: Hex; sk: number }[];  // sk = index into session_keys
  tx_commitments: Hex[];               // HMAC tx commitments (ADR-015), order-shuffled
  nonce_commitments: Hex[];            // HMAC (from,nonce) commitments, shuffled
  flags?: { has_tx: boolean; has_block: boolean; has_unapproved_tx: boolean; has_violation: boolean }; // privacy ≥ 1
  epoch_id: number; kek_id: Hex;       // which KEK wraps the DEK
  wrapped_dek: Hex;                    // L4
  iv: Hex;                             // L4
  payload_ct_hash: Hex;
  batch_sig: Hex;
}
```

The frame encoding (CBOR) and padding are defined in L3 §4. Encryption is defined in L4.

---

## 6. Anchors [NORMATIVE]

```
anchor_leaves = [ (agent_key: bytes32, lane: uint32, seq_to: uint64, chain_root: bytes32) ... ]
anchor_root   = StandardMerkleTree.of(anchor_leaves, ["bytes32","uint32","uint64","bytes32"]).root
```

Leaves are sorted by `(agent_key, lane)` before building the tree, so manifests are deterministic. One leaf per (agent, lane) per anchor: the latest checkpoint.

---

## 7. EIP-712 statements [NORMATIVE]

Domain (all statements):

```ts
const domain = { name: "AgentFlightRecorder", version: "1", chainId: <identity chain id> } as const;
```

The identity chain ID is the ERC-8004 chain from `agent_id`. Statements without an agent (e.g. ReaderKey) use chainId 8453.

```ts
const types = {
  Delegation: [
    { name: "agentKey",   type: "bytes32" },
    { name: "lane",       type: "uint32"  },
    { name: "sessionKey", type: "address" },
    { name: "notBefore",  type: "uint64"  },   // unix seconds
    { name: "notAfter",   type: "uint64"  },
    { name: "scope",      type: "uint32"  },   // bitmask: 1=records, 2=tx intents, 4=keygrants, 8=may sub-delegate (§7.1)
    { name: "recorder",   type: "string"  },   // recorder version string
    { name: "nonce",      type: "uint256" },   // random
  ],
  Revocation: [
    { name: "agentKey",   type: "bytes32" },
    { name: "sessionKey", type: "address" },
    { name: "effectiveAt",type: "uint64"  },   // records signed after this are invalid
    { name: "reason",     type: "string"  },
  ],
  AgentProfile: [
    { name: "agentKey",     type: "bytes32" },
    { name: "privacyLevel", type: "uint8"   },
    { name: "retentionDays",type: "uint32"  },
    { name: "watchedHash",  type: "bytes32" }, // keccak of JCS(watched addresses list)
    { name: "readersHash",  type: "bytes32" }, // keccak of JCS(reader pubkeys list)
    { name: "version",      type: "uint64"  }, // monotonically increasing
  ],
  ReaderKey: [
    { name: "owner",     type: "address" },
    { name: "x25519",    type: "bytes32" },
    { name: "label",     type: "string"  },
    { name: "notAfter",  type: "uint64"  },
  ],
  KeyGrant: [
    { name: "agentKey",  type: "bytes32" },
    { name: "epochId",   type: "uint32"  },
    { name: "kekId",     type: "bytes32" },
    { name: "reader",    type: "bytes32" },    // x25519 pubkey
    { name: "encHash",   type: "bytes32" },    // keccak of HPKE enc‖ct
  ],
  Approval: [
    { name: "agentKey",      type: "bytes32" },
    { name: "lane",          type: "uint32"  },
    { name: "requestSeq",    type: "uint64"  },
    { name: "requestHash",   type: "bytes32" },  // record_hash of the approval_request
    { name: "decision",      type: "uint8"   },  // 1 approved, 2 rejected
    { name: "expiresAt",     type: "uint64"  },
  ],
  ApprovalAttestation: [
    { name: "agentKey",      type: "bytes32" },
    { name: "lane",          type: "uint32"  },
    { name: "requestSeq",    type: "uint64"  },
    { name: "requestHash",   type: "bytes32" },
    { name: "decision",      type: "uint8"   },
    { name: "approver",      type: "string"  },  // "slack:T/U", "telegram:123"
    { name: "attestedAt",    type: "uint64"  },
  ],
  Attestation: [
    { name: "agentKey",      type: "bytes32" },
    { name: "lane",          type: "uint32"  },
    { name: "seqTo",         type: "uint64"  },
    { name: "chainRoot",     type: "bytes32" },
    { name: "verdict",       type: "uint8"   },  // 1 pass, 2 pass_with_findings, 3 fail
    { name: "findingsHash",  type: "bytes32" },
    { name: "scope",         type: "string"  },  // free text, e.g. "Q3-2026 SOC2 sample"
  ],
  CheckpointStatement: [                          // anchor service signs this into checkpoint entities
    { name: "agentKey",      type: "bytes32" },
    { name: "lane",          type: "uint32"  },
    { name: "seqTo",         type: "uint64"  },
    { name: "chainRoot",     type: "bytes32" },
    { name: "anchorRoot",    type: "bytes32" },
    { name: "anchorChainId", type: "uint64"  },
    { name: "anchorTx",      type: "bytes32" },
  ],
} as const;
```

**Delegation validity at record time:** a record signed by `sk` is valid iff there is a `Delegation` with `sessionKey = sk`, `agentKey` and `lane` matching, `notBefore ≤ ts/1000 ≤ notAfter` **and** the record is anchored before `notAfter + 1h`. The second condition stops backdating with an expired key, because anchors bound time. Other conditions: no `Revocation` with `effectiveAt` ≤ the anchor time of the record's batch, `scope & 1`, and the delegation signer was `ownerOf(tokenId)` at the delegation's `notBefore`.

### 7.1 Sub-delegation (recorder identity keys)

Long-running servers can't ask a human to sign a delegation every 24 h. The operator therefore signs **one** `Delegation` to a **recorder identity key** (TTL ≤ 30 days, `scope` includes `8`, key held in KMS or an encrypted keystore). That key then signs 24 h `Delegation`s for ephemeral session keys, using the same EIP-712 type and domain.

Verifier rules:
- Chain depth ≤ 2 (operator → recorder identity key → session key).
- The child's `[notBefore, notAfter]` ⊆ the parent's.
- The child's `scope` ⊆ the parent's `scope` minus `8` (no further sub-delegation).
- `agentKey` and `lane` must be equal.
- Revoking a parent invalidates its children from `effectiveAt`.

---

## 8. Evidence lock address [NORMATIVE]

```
EVIDENCE_LOCK_ADDRESS = lowercase( last20bytes( keccak256( utf8("AFR_EVIDENCE_LOCK_V1") ) ) )
```

Nobody knows a private key for it: it's a hash output, not a derived public key.

---

## 9. Public API of `@afr/core`

```ts
// ids
export function parseAgentId(id: string): { chainId: bigint; registry: Hex; tokenId: bigint };
export function agentKey(id: string): Hex;
export function batchId(agentKey: Hex, lane: number, seqFrom: bigint): Hex;
export function epochIdFor(date: Date, rotation?: number): number;

// canonical + hashing
export function jcs(value: unknown): string;               // throws on floats/undefined/bigint
export function hashHeader(h: RecordHeaderV1): Hex;
export function commit(domain: CommitDomain, value: unknown, salt: Hex): Hex;

// building
export interface BuildInput { /* type-specific fields, see §3 */ }
export function buildHeader(input: BuildInput, chainState: { seq: bigint; prevHash: Hex }): RecordHeaderV1;
// commitments must cover the FULL value, so they are returned alongside the (possibly truncated) body
export function buildBody(parts: BodyParts, salt: Hex, opts: { maxBytes: number }): { body: RecordBodyV1; commit: Commitments };
export function commitmentsFor(body: RecordBodyV1): Commitments;   // recompute for verification; skips truncated fields

// signing
export interface Signer { address: Hex; signDigest(raw: Hex): Promise<Hex> | Hex; }
export function signRecord(signer: Signer, recordHash: Hex): Promise<Hex>;
export function recoverRecordSigner(recordHash: Hex, sig: Hex): Promise<Hex>;

// batch + chain
export function batchRoot(entries: { seq: bigint; hash: Hex }[]): Hex;
export function batchProof(entries: …, seq: bigint): Hex[];
export function chainRoot(prev: Hex, batchRoot: Hex, seqTo: bigint): Hex;
export function batchDigest(p: BatchDigestInput): Hex;

// anchors
export function anchorTree(leaves: AnchorLeaf[]): { root: Hex; proof(leaf: AnchorLeaf): Hex[]; dump(): unknown };
export function verifyAnchorProof(root: Hex, leaf: AnchorLeaf, proof: Hex[]): boolean;

// eip712
export const EIP712_TYPES: typeof types;
export function eip712Domain(chainId: number | bigint): …;
export function hashTyped<T extends keyof typeof types>(chainId, primaryType: T, message): Hex;
export function verifyTyped<T>(chainId, primaryType: T, message, sig, expected: Hex): Promise<boolean>;

// constants
export * from "./constants";

// schemas
export const RecordHeaderV1Schema, RecordBodyV1Schema, BatchPublicV1Schema, …;
```

---

## 10. File layout

```
packages/core/
├─ src/
│  ├─ constants.ts
│  ├─ ids.ts
│  ├─ jcs.ts
│  ├─ hash.ts            # keccak helpers, commit()
│  ├─ record/
│  │  ├─ types.ts
│  │  ├─ schema.ts       # zod
│  │  ├─ build.ts
│  │  └─ verify.ts       # header-level checks (per-type required fields)
│  ├─ sign.ts
│  ├─ merkle.ts          # batch + anchor trees (wrap @openzeppelin/merkle-tree)
│  ├─ chain.ts           # chainRoot, batchDigest
│  ├─ eip712.ts
│  └─ index.ts
├─ test/
│  ├─ jcs.test.ts
│  ├─ record.test.ts
│  ├─ chain.property.test.ts
│  ├─ merkle.test.ts
│  ├─ eip712.test.ts
│  └─ (vectors.test.ts lives in packages/test-vectors/test: core may not import other packages)
└─ package.json
```

---

## 11. Test vectors (`packages/test-vectors`)

Generate them with `pnpm --filter @afr/test-vectors gen`, using fixed keys and salts. **Commit the output.** A vector change is a breaking change and needs an ADR.

```
vectors/
├─ jcs.json               # inputs → canonical strings (incl. unicode, nested, key order)
├─ agent_id.json          # ids → agent_key
├─ commit.json            # (domain, value, salt) → commitment
├─ records.json           # header → record_hash → sig (fixed session key 0x…01)
├─ chain.json             # 5 records, 2 batches → batch_roots, chain_roots, digests
├─ merkle.json            # leaves → root, proofs
├─ anchor.json            # leaves → root, proofs (also consumed by Foundry test)
├─ eip712.json            # each statement type → digest + sig (fixed operator key 0x…02)
├─ lock_address.json
└─ negative/              # mutated records/batches that MUST fail verification, with expected error codes
```

Fixed test keys (never use outside tests):
- session key: `0x0000000000000000000000000000000000000000000000000000000000000001`
- operator key: `0x…0002`
- reader X25519 secret: `0x…0003` (L4 vectors)

---

## 12. Tests and acceptance criteria

| # | Test | Acceptance |
|---|---|---|
| T1 | JCS matches RFC 8785 Appendix vectors | 100 % |
| T2 | `jcs()` throws on float, NaN, bigint, undefined, non-NFC strings (or normalises them) | ✅ |
| T3 | Property: any single-byte mutation of any header field changes `record_hash` | 10k runs |
| T4 | Property: for random chains, reordering/removing/inserting any record breaks `prev_hash` or `seq` verification | 10k runs |
| T5 | Merkle proofs verify for every leaf. A forged leaf fails | ✅ |
| T6 | Anchor root computed in TS == computed in Solidity (Foundry FFI test reads `anchor.json`) | ✅ |
| T7 | EIP-712 digests match `viem.hashTypedData` and an independent implementation (ethers in test only) | ✅ |
| T8 | `buildHeader` rejects missing per-type required fields | ✅ |
| T9 | Benchmark: build + hash + sign ≤ 1 ms p99 for a 2 KiB header on CI runner | ✅ |
| T10 | Zero runtime dependencies beyond the listed ones. No Node built-ins (runs in browser) | lint |

---

## 13. Pitfalls

- **Never** hash `JSON.stringify` output. Always `jcs()`.
- **Never** put bigints or numbers > 2^31 into hashed objects. Use decimal strings.
- Checksummed addresses inside records break hashes when another tool lowercases them. Always lowercase.
- `@openzeppelin/merkle-tree` sorts leaves by hash by default when building (`sortLeaves: true`). That's fine for roots. Proofs must be looked up by leaf value, never by index.
- EIP-191 over a 32-byte **raw** digest ≠ EIP-191 over the hex **string**. Use `{ raw }`.
- `abi.encodePacked` with a string prefix in the chain root: in TS use `encodePacked(["string","bytes32","bytes32","uint64"], …)`.

---

## 14. Vibecoding prompts

> Paste these one at a time into your coding agent. Each prompt assumes the agent has read `CLAUDE.md`, this file and the Architecture §8/§21.

1. "Create `packages/core` with the file layout in L1 §10. Implement `constants.ts` exactly as Architecture §21, including `deriveLockAddress()`. Add Vitest. No other files yet."
2. "Implement `jcs.ts` using the `canonicalize` package. Add guards that throw on floats, bigint, undefined and non-NFC strings (normalise NFC instead of throwing). Add tests including the RFC 8785 appendix vectors."
3. "Implement `record/types.ts` and `record/schema.ts` from L1 §3 exactly. Zod schemas must be `.strict()` and enforce lowercase hex, decimal-string U64, and per-type required fields (L1 §3.1 table)."
4. "Implement `hash.ts` (`commit()`) and `record/build.ts` (`buildHeader`, `buildBody`, `commitmentsFor`) per L1 §3.2–3.4, including truncation and redaction semantics. Inject salt, never generate randomness inside core."
5. "Implement `sign.ts` using viem's `signMessage({ message: { raw } })` and `recoverMessageAddress`. Then `chain.ts` (chainRoot, batchDigest) per L1 §5 using viem `encodePacked`/`encodeAbiParameters`."
6. "Implement `merkle.ts` wrapping `@openzeppelin/merkle-tree` for batch leaves `[uint64,bytes32]` and anchor leaves `[bytes32,uint32,uint64,bytes32]`. Anchor leaves are sorted by (agent_key, lane) before building."
7. "Implement `eip712.ts` with the exact types in L1 §7 and helpers `hashTyped`/`verifyTyped`."
8. "Create `packages/test-vectors` with a `gen` script producing every file in L1 §11 from the fixed test keys. Add `vectors.test.ts` in core that recomputes every vector and asserts equality. Add negative vectors with expected error codes."
9. "Add fast-check property tests T3 and T4 and a micro-benchmark T9."
