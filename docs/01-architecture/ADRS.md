# Architecture Decision Records

Format: **Context → Decision → Consequences → Status**. ADRs are append-only. To change one, supersede it with a new ADR and mark the old one `Superseded by ADR-xxx`.

| ADR | Title | Status |
|---|---|---|
| 001 | TypeScript monorepo for everything except contracts | Accepted |
| 002 | RFC 8785 JCS for hashed encoding; CBOR for batch transport | Accepted |
| 003 | keccak256 + EIP-191/EIP-712 (EVM-native crypto) | Accepted |
| 004 | Batches, not one entity per action | Accepted |
| 005 | Writer account ≠ signer; provenance from signatures only | Accepted |
| 006 | Records split into header (hashed) and body (committed) | Accepted |
| 007 | Lanes: one hash chain per recorder instance | Accepted |
| 008 | Envelope encryption: DEK per batch, KEK per epoch, HPKE X25519 to readers | Accepted |
| 009 | Own encryption code over `arkiv-encryption` package | Accepted |
| 010 | OpenZeppelin StandardMerkleTree everywhere | Accepted |
| 011 | Evidence lock via ownership transfer to keyless address | Accepted, pending P2 spike |
| 012 | Readonly + permissionlessExtension on evidence | Accepted |
| 013 | Expiry strategy: upfront by default → amended 2026-11-04 (S6): rolling by default, upfront only ≤ 30 d | Accepted (amended) |
| 014 | Tiered retention (payload vs. proofs) | Proposed (P6) |
| 015 | HMAC tx commitments for hosted watcher | Accepted |
| 016 | Two-phase capture (call + result records) | Accepted |
| 017 | Journal before forward/broadcast; fail-open by default | Accepted |
| 018 | Rollup anchoring with Arkiv-published manifest | Accepted |
| 019 | Postgres-only control plane (no Redis/Kafka at MVP) | Accepted |
| 020 | Browser-side decryption; reader keys never leave the client | Accepted |
| 021 | Python SDK talks to a local recorder sidecar | Accepted |
| 022 | Delegations and revocations are separate public entities | Accepted |
| 023 | Approvals: attested (service-signed) and cryptographic (EIP-712) | Accepted |

---

### ADR-001 — TypeScript monorepo

- **Context:** Arkiv SDK, viem and the official MCP SDK are TS-first. The verifier must run in browser and Node.
- **Decision:** pnpm + Turborepo monorepo, TS (ESM, Node ≥ 22.10) for all runtime code. Solidity/Foundry for contracts. Python SDK is a thin client.
- **Consequences:** One crypto implementation shared by recorder, verifier and dashboard, so formats can't drift between them. Python users need the sidecar (ADR-021).

### ADR-002 — JCS for hashing, CBOR for transport

- **Context:** Hashes must be reproducible by any verifier in any language. Transport must be compact (128 KiB create limit).
- **Decision:** Hashed objects (record headers, commitments' values) use **RFC 8785 JCS**. The batch frame on the wire is **deterministic CBOR**, compressed with raw deflate before encryption.
- **Consequences:** JSON number pitfalls. Rule: in hashed AFR structures only integers in [0, 2^31) may be JSON numbers; seq, ts, wei and token amounts are decimal **strings** (L1 §3.5). No floats anywhere in hashed data (USD values are integer cents as strings). Lint rule: `no-float-in-record`.

### ADR-003 — EVM-native crypto

- **Decision:** keccak256. Session keys are secp256k1 and sign with EIP-191 (`signMessage({ message: { raw: record_hash } })`). Operator statements use EIP-712 typed data.
- **Consequences:** Wallets can sign delegations natively. Solidity can verify everything. Domain separation comes from domain strings (`AFR_*_V1`) and the EIP-712 domain.

### ADR-004 — Batches

- **Context:** Arkiv charges per entity and per byte-time. Limits: 128 KiB bytes per create, 32 attributes.
- **Decision:** Up to ~1,000 records per `afr.batch.v1` entity, closed at 5 s or 96 KiB. Single records are provable via Merkle path.
- **Consequences:** Per-action public queries are impossible at privacy 0/1 (accepted). Privacy level 2 adds sparse `afr.action.v1` entities for tx actions only.

### ADR-005 — Writer ≠ signer

- **Context:** Arkiv guidance says "owner is not payload provenance". Session keys would each need tGLM funding.
- **Decision:** A funded **writer account** submits Arkiv txs. Every payload is self-authenticating through session-key/operator signatures. The verifier ignores `$owner`/`$creator` except as discovery hints.
- **Consequences:** Hosted gas sponsorship becomes possible later (writer run by AFR, signer stays with the customer). Spam entities can't pass verification.

### ADR-006 — Header/body split

- **Decision:** `record_hash` covers the **header** only. The header contains salted commitments to the body parts (args, result, context, output, calldata). The body (plaintext + salt) sits only in the encrypted section.
- **Consequences:** Signatures and chain checks don't need plaintext. Plaintext can be redacted or crypto-shredded without breaking chain verification. Full verification recomputes commitments.

### ADR-007 — Lanes

- **Context:** "Monotonic seq, no gaps" is impossible with several concurrent recorder instances for one agent.
- **Decision:** Each recorder instance owns a **lane** (`uint32`), assigned by the API (or config) and authorised in the delegation. `seq` is per (agent, lane). MVP uses lane 0 only.
- **Consequences:** Verifier, watcher and anchors work per lane. The dashboard merges lanes by `ts` for display (labelled as "approximate cross-lane order").

### ADR-008 — Envelope encryption

- **Decision:** A random 256-bit DEK per batch (AES-256-GCM, AAD bound to batch identity). The DEK is wrapped under an **epoch KEK** (per agent per month). The KEK is HPKE-wrapped (X25519) to each reader in `afr.keygrant.v1` entities.
- **Consequences:** Historic auditor grants cost one keygrant per epoch, not per batch. Revocation = early epoch rotation. Crypto-shredding = destroy the KEK. Wallet keys aren't used for decryption (wallet `eth_decrypt` is deprecated). Readers register X25519 keys signed by their wallet.

### ADR-009 — Own encryption code

- **Context:** `arkiv-encryption@0.1.0` uses AES-GCM without AAD (its own docs say envelopes can be replayed elsewhere), has a 100 KB plaintext policy, and does no sharing.
- **Decision:** Implement the L4 scheme on `@noble/ciphers` / WebCrypto + `@hpke/core`, with AAD binding and test vectors.
- **Consequences:** More code to audit. Commission an external crypto review before v1 GA.

### ADR-010 — StandardMerkleTree

- **Decision:** Use `@openzeppelin/merkle-tree` StandardMerkleTree (double-hashed leaves, sorted pairs) for batch roots and anchor roots.
- **Consequences:** Solidity `MerkleProof.verify` works on-chain. Sorted pairs lose positional info, so `seq` is inside the leaf to compensate.

### ADR-011 — Evidence lock

- **Context:** Readonly entities can still be **deleted** by their owner. A leaked writer key could delete evidence.
- **Decision:** Atomically in one `executeBatch`: create the entity (readonly, permissionlessExtension) and `changeOwnership` of its **predicted key** to `EVIDENCE_LOCK_ADDRESS` (keyless, derived from a nothing-up-my-sleeve string).
- **Consequences:** No one can delete or transfer locked evidence. Anyone can extend it. Early erasure is only possible through crypto-shredding. **Spike in P2:** confirm (a) `predictEntityKeys` + same-batch ownership change works, (b) transfer to an arbitrary address is allowed. **Fallback:** don't lock; rely on detectability (gaps + anchors) and the Postgres mirror.
- **Spike result (S3, 2026-11-04, SDK 1.0.1/Rabdi):** confirmed. (a) The predicted key + same-batch `changeOwnership` lands atomically; the created key equals the prediction. (b) Transfer to the keyless lock address is allowed. On the locked entity, patch, transfer and delete by the writer fail with `NotOwner`. Fallback not needed.

### ADR-012 — Readonly + permissionlessExtension

- **Decision:** All evidence entities are `readonly: true`, and all except attestations/delegations are `permissionlessExtension: true`.
- **Consequences:** Auditors, insurers and counterparties can keep evidence alive past the customer's retention if they pay. That's a feature (litigation hold). It conflicts with data minimisation, which is why crypto-shredding is the erasure mechanism.
- **Spike result (S9, 2026-11-04):** confirmed on a locked, readonly, `permissionlessExtension` entity: a non-owner extended it on-chain, and a stranger's `eth_call` passes. Without the flag, extension by a non-owner fails (`NotOwner`).

### ADR-013 — Upfront expiry

- **Decision:** Default: create with `expiration = retention period` (`ExpirationTime.fromDays(retention_days)`). Optional `rolling` mode: create with 90 days, extension service renews (P6).
- **Consequences:** No dependency on a renewal service for correctness. Higher upfront cost. Revisit once Arkiv mainnet pricing is known.
- **Amendment (S6, 2026-11-04, SDK 1.0.1/Rabdi):** upfront expiry beyond ≈ 182.5 d is impossible (`MAX_LIFETIME` = 7,884,000 blocks from the create/extension block). Gas also grows with bytes × lifetime: a 96 KiB create at > ≈ 55 d breaks the write-safety bound (2 × estimate ≤ half block). New rule: `upfront` only for retention ≤ 30 d. Otherwise `rolling` is the **default**: create with 30 d, and an extension service (any funded account, thanks to ADR-012) extends in ≤ ≈ 110 d chunks before expiry. The extension service moves from P6 into the P2/P3 path for any retention > 30 d. Correctness now depends on that service running; detectability (gaps + anchors + mirror) still covers a lapse.

### ADR-014 — Tiered retention (proposed)

- **Decision (proposed):** For retention > N years, write a compact `afr.proof.v1` entity (public sections only: hashes, signatures, roots) with long expiry, and let the full batch expire earlier.
- **Consequences:** Proof survives cheaply. Content needs the customer's archive (evidence pack in their own cold storage).

### ADR-015 — HMAC tx commitments

- **Decision:** Recorder publishes `HMAC(watch_key, AFR_TX_V1‖chainId‖txHash)` per tx intent (batch public section + intent API). Hosted watcher holds the watch key and checks observed txs.
- **Consequences:** Public observers can't link agent→tx at privacy 0. The hosted watcher can, which it needs to. Watch key compromise only reveals linkage, not content.

### ADR-016 — Two-phase capture

- **Decision:** `tool_call` is recorded before forwarding. `tool_result` (with `ref_seq`) is recorded after the response. The same pattern applies to `tx_sign` → `tx_broadcast` and `approval_request` → `approval`.
- **Consequences:** A crash during a tool call leaves a dangling call. The verifier/dashboard shows "no result recorded" instead of losing the call.

### ADR-017 — Journal first, fail-open

- **Decision:** A record is committed to the local journal **before** the proxied request is forwarded (calls) or the tx is broadcast (tx_sign). If the recorder fails, default is **fail-open** (agent proceeds, recorder writes a `gap` record later). With guardrails, the operator can choose **fail-closed**.
- **Consequences:** Unlogged-tx detection is sound for txs passing through the hook. Fail-open trades evidence completeness for availability, and the gap is itself evidence.

### ADR-018 — Rollup anchoring

- **Decision:** One Base tx anchors a StandardMerkleTree root over many `(agent_key, lane, seq_to, chain_root)` leaves. The full leaf list (manifest) is published as an `afr.anchor.v1` entity. Per-leaf `afr.checkpoint.v1` entities carry proofs for easy querying.
- **Consequences:** Gas stays flat in the number of agents. The manifest must be retrievable to build proofs, so it's also mirrored in Postgres and included in evidence packs.

### ADR-019 — Postgres-only control plane

- **Decision:** Postgres 16 for state, `pg-boss` for jobs, LISTEN/NOTIFY for fan-out. No Redis/Kafka until load requires it.
- **Consequences:** Fewer moving parts. Revisit at >10k agents.

### ADR-020 — Browser-side decryption

- **Decision:** The dashboard decrypts in the browser with the user's reader key (IndexedDB, WebCrypto non-extractable where possible). Servers never get plaintext or private reader keys.
- **Consequences:** Rich search runs locally (DuckDB-WASM). Server-side alerting on plaintext conditions needs the customer-hosted watcher or recorder-emitted public flags.

### ADR-021 — Python via sidecar

- **Decision:** Python SDK sends capture events to a local recorder sidecar (`fr-proxy --sidecar`) over a unix socket or localhost HTTP. All crypto happens in TS.
- **Consequences:** One crypto implementation. Python users run one extra process (shipped as a Docker image and an npx command).

### ADR-022 — Delegations as separate entities

- **Context:** The original spec put delegations inside the encrypted agent payload, but verifiers need them publicly.
- **Decision:** `afr.delegation.v1` and `afr.revocation.v1` are public, readonly, locked entities carrying EIP-712 signatures by the operator.
- **Consequences:** Session-key addresses are public. That's acceptable: they're ephemeral and reveal only recorder restarts.

### ADR-023 — Two approval strengths

- **Decision:** `approval` records carry `method: "attested" | "eip712"`. Attested = Slack/Telegram identity verified by the approvals service, which signs an `ApprovalAttestation` with its KMS key. EIP-712 = the approver's own wallet signature.
- **Consequences:** Policies can require `eip712` for high-value actions. Auditors can see which strength was used.
