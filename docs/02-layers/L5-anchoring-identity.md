# L5 — Anchoring (Base) & Identity (ERC-8004)

| | |
|---|---|
| Parts | `contracts/` (Foundry: `RecorderAnchor`, later `AfrKillSwitchModule`), `apps/anchor` (anchor service + extension jobs), `packages/identity` (ERC-8004 adapter) |
| Depends on | `@afr/core`, `@afr/store`, `viem`, OpenZeppelin Contracts 5.x (`MerkleProof`), AWS KMS |
| Requirements | ANC-01…ANC-06, VER-03, WAT-04 (anchor lag) |
| Phase | P3 (contract, service, identity read), P5 (Base mainnet), P6 (validation responses, kill-switch module), P8 (reputation) |

---

## 1. Why anchor

Arkiv still runs with centralised block production and has replaced its testnets before. Anchoring periodic roots on Base gives:

1. A **settlement-grade timestamp**: each record existed no later than the anchoring block.
2. **Rewrite detection**: any change to Arkiv history no longer matches the anchored root.
3. **Survivability**: if Arkiv disappears, journals or evidence packs plus Base anchors still verify.

---

## 2. `RecorderAnchor` contract [NORMATIVE interface]

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title RecorderAnchor — anchors AFR checkpoint roots. Immutable, holds no funds.
contract RecorderAnchor {
    address public immutable admin;                 // Safe multisig; can only manage the recorder allowlist
    mapping(address => bool) public isRecorder;
    uint64 public epoch;                            // increments per anchor
    mapping(uint64 => bytes32) public rootOf;       // epoch → root
    mapping(bytes32 => uint64) public epochOf;      // root → epoch (0 = unknown; epochs start at 1)

    event RecorderSet(address indexed recorder, bool allowed);
    event Anchored(uint64 indexed epoch, bytes32 indexed root, uint32 leafCount, bytes32 manifestKey, address indexed recorder);
    event AgentAnchored(uint64 indexed epoch, bytes32 indexed agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot);

    error NotAdmin(); error NotRecorder(); error ZeroRoot(); error DuplicateRoot(); error EmptyAnchor();

    constructor(address admin_, address[] memory recorders) {
        admin = admin_;
        for (uint256 i; i < recorders.length; ++i) { isRecorder[recorders[i]] = true; emit RecorderSet(recorders[i], true); }
    }

    modifier onlyRecorder() { if (!isRecorder[msg.sender]) revert NotRecorder(); _; }

    function setRecorder(address r, bool allowed) external {
        if (msg.sender != admin) revert NotAdmin();
        isRecorder[r] = allowed; emit RecorderSet(r, allowed);
    }

    /// Rollup anchor: root of StandardMerkleTree over (bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot)
    function anchorRoot(bytes32 root, uint32 leafCount, bytes32 manifestKey) external onlyRecorder returns (uint64 e) {
        if (root == bytes32(0)) revert ZeroRoot();
        if (leafCount == 0) revert EmptyAnchor();
        if (epochOf[root] != 0) revert DuplicateRoot();
        e = ++epoch; rootOf[e] = root; epochOf[root] = e;
        emit Anchored(e, root, leafCount, manifestKey, msg.sender);
    }

    /// Single-agent anchor (self-host / dedicated). Root = leaf hash (single-leaf StandardMerkleTree).
    function anchor(bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot) external onlyRecorder returns (uint64 e) {
        bytes32 leaf = leafHash(agentKey, lane, seqTo, chainRoot);
        if (epochOf[leaf] != 0) revert DuplicateRoot();
        e = ++epoch; rootOf[e] = leaf; epochOf[leaf] = e;
        emit Anchored(e, leaf, 1, bytes32(0), msg.sender);
        emit AgentAnchored(e, agentKey, lane, seqTo, chainRoot);
    }

    function leafHash(bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(agentKey, lane, seqTo, chainRoot))));
    }

    function verify(uint64 e, bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot, bytes32[] calldata proof)
        external view returns (bool)
    {
        bytes32 root = rootOf[e];
        return root != bytes32(0) && MerkleProof.verifyCalldata(proof, root, leafHash(agentKey, lane, seqTo, chainRoot));
    }
}
```

**Properties:**
- No upgradeability, no `selfdestruct`, no ETH receive. The admin can only edit the allowlist.
- The block timestamp of the `Anchored` event is the time bound. `rootOf` lets anyone verify on-chain, for example a lending protocol checking an agent's log freshness.
- The `manifestKey` is the Arkiv entity key of the `afr.anchor.v1` manifest (0 for single anchors).

**Foundry tests** (`contracts/test/RecorderAnchor.t.sol`):
- Unit: allowlist, reverts, events, epoch increments.
- **Vector test:** read `packages/test-vectors/vectors/anchor.json` via `vm.readFile`, and assert that `leafHash` and `verify` match the TS-generated root/proofs.
- Fuzz: random leaves → build the tree in Solidity test helper → verify.
- Invariant: `epoch` == number of successful anchors. `rootOf[epochOf[r]] == r`.
- Gas snapshot: `anchorRoot` < 60k execution gas in steady state, i.e. excluding the 21k intrinsic cost. Measured: 77.7k per transaction including intrinsic, so ≈ 56.7k execution. The first anchor ever costs ≈ 17k more for the `epoch` slot's 0 → 1 write.

**Deployment:** `forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify`. Use CREATE2 with a fixed salt for the same address across chains. Record addresses in `packages/core/src/anchors.ts` (`ANCHOR_CONTRACTS[chainId] = [{address, fromBlock, version}]`).

---

## 3. Anchor service (`apps/anchor`)

### 3.1 Responsibilities

1. Collect pending checkpoints (from API notices **and** by scanning Arkiv for new batches from known writers, as a fallback).
2. Validate each one cheaply: the batch entity exists, `batch_sig` recovers to a session key with a valid delegation, `chain_root` follows the previous anchored checkpoint for that lane (or rewinds are flagged).
3. Build the rollup tree, publish the manifest to Arkiv, send `anchorRoot` on Base.
4. Track confirmation depth: `included` → `safe` → `finalized` (Base block tags).
5. Publish `afr.checkpoint.v1` entities (one per leaf, carrying a `CheckpointStatement` signature and Merkle proof).
6. Notify the API (which notifies recorders: batch → `anchored`).
7. Run the **extension job** (rolling expiry) and the **anchor-lag detector** feed for the watcher.

### 3.2 Loop

```
every 30 s:
  pending = db.checkpoints where status='pending' ordered by received_at
  due = now - last_anchor_at >= cadence(plan)  OR  count(distinct agent,lane) >= N_MAX (500)
  if !due: continue
  leaves = latest validated checkpoint per (agent_key, lane) among pending   // older ones are covered by chain_root
  sort leaves by (agent_key, lane)
  tree = anchorTree(leaves)
  manifestKey = store.put(afr.anchor.v1 {anchor_root, leaves, tree.dump(), contract, chain}) → await verified
  tx = anchorRoot(tree.root, leaves.length, manifestKey) via KMS signer   // nonce mgmt, EIP-1559, replacement after 3 blocks
  wait receipt (1 conf) → status 'included', epoch from event
  store.put(afr.checkpoint.v1 × leaves, via executeBatch chunks of ≤ 20 creates)  // each with proof
  db: checkpoints → anchored(epoch, tx, block); covered older pending → anchored (superseded)
  later job: poll 'safe' / 'finalized' tags → update status
```

- **Rewind detection:** a new checkpoint for (agent, lane) whose chain doesn't extend the last anchored `chain_root` (it has a lower `seq_to`, or the same `seq_to` with a different root) is **not anchored**. It raises `BROKEN_CHAIN`/`EQUIVOCATION` to the watcher.
- **Cost:** about 60k gas per anchor plus calldata. At a 10-minute cadence that's ~4,300 anchors/month in total, independent of agent count.
- **Dedicated anchors** (Business/Enterprise plans): shorter cadence for specific agents. Same contract, separate leaf sets.

### 3.3 KMS signer

- AWS KMS key spec `ECC_SECG_P256K1`, usage `SIGN_VERIFY`.
- viem custom account: `signTransaction` → serialise → `KMS.Sign(MessageType=DIGEST, SigningAlgorithm=ECDSA_SHA_256)` on keccak digest → parse DER → normalise `s` (low-s) → recover `v` by trying both recovery IDs against the known address.
- IAM: only the anchor task role may call `kms:Sign` on that key. CloudTrail alerts on any other principal.
- Nonce: single-instance service (leader lock via `pg_advisory_lock`). Nonce comes from the DB, reconciled against `getTransactionCount(pending)` on start.

### 3.4 Database (shared Postgres, `anchor` schema)

```sql
CREATE TABLE anchor.anchors (
  epoch bigint PRIMARY KEY, chain_id bigint NOT NULL, contract bytea NOT NULL,
  root bytea NOT NULL UNIQUE, leaf_count int NOT NULL, manifest_key bytea NOT NULL,
  tx_hash bytea NOT NULL, block_number bigint, block_time timestamptz,
  status text NOT NULL CHECK (status IN ('sent','included','safe','finalized','failed')),
  created_at timestamptz NOT NULL DEFAULT now()
);
-- checkpoints table lives in the API schema (L8); anchor service updates status/epoch/proof
```

### 3.5 Extension job (rolling expiry, v1)

Daily: for each agent with `expiry=rolling`, query batches/checkpoints with `$expiresAt < now + 30d` created by the agent's writers, then `extendEntity` to `min(created + retention, now + 90d)`. Cost is metered per agent (`usage_events.kind='extension'`).

---

## 4. ERC-8004 adapter (`packages/identity`)

> ⚠️ ERC-8004 field and function names have changed between drafts. Confirm the deployed registry ABIs and the current registration-file schema at implementation time (P3 task 1). Keep everything ERC-8004-specific inside this package.

### 4.1 What we use

| Registry | Use | Calls |
|---|---|---|
| **Identity** (ERC-721 + URI storage) | Resolve the agent, find its operator, read the registration file | `ownerOf(agentId)`, `tokenURI(agentId)` (a.k.a. `agentURI`), `getMetadata(agentId, key)` (e.g. `agentWallet`), `Transfer` events for owner history; `register(...)` / `setAgentURI(...)` from the dashboard |
| **Validation** | Auditors publish verdicts referencing AFR attestations | `validationRequest(validator, agentId, requestURI, requestHash)`, `validationResponse(requestHash, response, responseURI, responseHash, tag)` |
| **Reputation** (P8) | Feedback citing AFR evidence | `giveFeedback(agentId, value, decimals, tag1, tag2, endpoint, feedbackURI, feedbackHash)` |

### 4.2 Registration file: the AFR service entry

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "Treasury Rebalancer",
  "description": "…",
  "services": [
    { "name": "MCP", "endpoint": "https://agent.example.com/mcp", "version": "2025-06-18" },
    {
      "name": "afr",
      "endpoint": "https://verify.afr.dev/agents/eip155:8453:0xregistry:42",
      "version": "afr/1",
      "afr": {
        "agentKey": "0x…",
        "arkiv": { "chainId": 7794095, "schemas": ["afr.batch.v1", "afr.checkpoint.v1"], "writers": ["0x…"] },
        "anchor": { "chainId": 8453, "address": "0x…", "fromBlock": 123456 },
        "verifier": "npx @afr/cli verify agent eip155:8453:0xregistry:42"
      }
    }
  ],
  "registrations": [{ "agentId": 42, "agentRegistry": "eip155:8453:0xregistry" }],
  "supportedTrust": ["reputation", "crypto-economic", "validation"]
}
```

- The adapter reads `services` **or** `endpoints` (older drafts).
- The dashboard generates the updated file, offers hosting (IPFS pin via web3.storage/Pinata, or the customer's HTTPS), and prepares the `setAgentURI` tx for the operator to sign.
- The `writers` list here and in the signed `AgentProfile` must match. The verifier warns if they differ.

### 4.3 Operator resolution

```
operatorAt(agentId, timestamp):
  block = the last block with block.timestamp ≤ timestamp   (exponential search back from head, then bisection)
  return ownerOf(agentId) at that block                      (historical eth_call)
```

Why not a Transfer-log scan: public RPCs cap `eth_getLogs` (Base Sepolia: 200 blocks), and the registry is tens of millions of blocks old (SPIKES S11). Historical `eth_call` gives the same answer, the owner at the end of that block. The RPC must serve state and headers back to the delegation's `notBefore`; otherwise the result is `RPC_HISTORY_UNAVAILABLE`, never a guess. Before the mint it's `AGENT_NOT_REGISTERED`.

A delegation is valid only if its signer == `operatorAt(agentId, delegation.notBefore)`, **or** the signer is a recorder identity key whose parent delegation passes that test (L1 §7.1). Smart-contract owners (Safe): verify EIP-712 signatures through **ERC-1271** `isValidSignature` at the current block. A historic check isn't possible on most RPCs, so the verifier states this limit.

### 4.4 Public API

```ts
resolveAgent(agentId, rpc, uriOpts?): Promise<{ owner: Hex; uri: string; registration: Registration; afr?: AfrService; agentWallet?: Hex }>
operatorAt(agentId, ts, rpc): Promise<Hex>                       // ts: unix seconds (bigint)
verifyOperatorSig(agentId, typedData, sig, ts, rpc): Promise<{ ok: boolean; method: "ecdsa" | "erc1271"; operator: Hex; note?: string }>
buildRegistrationWithAfr(existing: Registration, afr: AfrService): Registration
encodeRegister(...), encodeSetAgentURI(...), encodeValidationResponse(...)
```

- `rpc` is a viem public client and must be on the agent id's chain (`CHAIN_MISMATCH`).
- Agent URIs: `data:application/json`, `https:` (no redirects), `ipfs:` only through a configured gateway. Plain `http:` is refused. Content is capped at 64 KiB and parsed as JSON, never executed.
- `verifyOperatorSig` tries ECDSA first, then ERC-1271 at the current block when the operator has code (the `note` says so).
```

### 4.5 Watched-address sanity check

If the registry exposes `agentWallet` metadata, the watcher/dashboard warns when that wallet is **not** in the agent's watched set. That catches a misconfiguration where the agent's real wallet goes unwatched.

---

## 5. Kill-switch module (v1, optional)

`AfrKillSwitchModule`: an ERC-7579 executor/hook module (or Safe Guard variant) installed on the agent's smart account.

- `pause()` can be called by a configured guardian (AFR alert executor key and/or the operator). After it, the hook rejects every execution except `unpause` by the operator.
- `revokeSessionKey(address)` for accounts using session-key validators (ERC-7579 / Safe 4337 module ecosystems), where supported.
- The watcher calls it on a critical alert if `kill_switch.auto = true`. Otherwise the UI offers one click.
- Ship with audits. Until it's audited, the feature is labelled beta, and webhook-based kill switches (customer code) are the default.

---

## 6. Tests and acceptance criteria

| # | Test |
|---|---|
| A1 | Foundry unit, fuzz, invariant suites. Vector parity with TS (`anchor.json`) |
| A2 | Anchor service on Anvil: 50 agents × 3 lanes → one anchor tx. Every checkpoint gets a proof that `verify()` accepts on-chain |
| A3 | Rewind attempt (lower seq_to) → not anchored, alert raised |
| A4 | KMS signer: sign/recover round-trip with LocalStack KMS (or a real dev key) |
| A5 | Crash between manifest publish and anchor tx → on restart, reuse the manifest and don't double-anchor (idempotent by root) |
| A6 | Identity: resolve a registered agent on Base Sepolia. `operatorAt` returns the right owner across a transfer |
| A7 | ERC-1271 operator signature (Safe) verifies |

## 7. Vibecoding prompts

1. "Create a Foundry project in `contracts/` with `RecorderAnchor.sol` exactly as L5 §2, OZ 5.x installed via forge. Write the tests in L5 §2 including the vector test reading `packages/test-vectors/vectors/anchor.json`."
2. "Write `script/Deploy.s.sol` using CREATE2 and a deploy README. Deploy to Base Sepolia, record the address in `packages/core/src/anchors.ts`."
3. "Create `apps/anchor`: Fastify-less worker with pg-boss, leader lock, the loop in L5 §3.2, a viem account backed by a pluggable signer (local key for dev, KMS for prod per §3.3). Tests A2, A3, A5 against Anvil + MemoryStore."
4. "Create `packages/identity` with the API in L5 §4.4. First task: fetch and record current ERC-8004 registry ABIs and addresses for Base and Base Sepolia into `src/abis/` with source links. Implement `resolveAgent`, `operatorAt` (Transfer log scan with caching), `verifyOperatorSig` (ECDSA + ERC-1271)."
