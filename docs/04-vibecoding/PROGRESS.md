# Progress Log

Update at the end of every coding session (see VIBECODING §2). Newest entries first.

## Status board

| Phase | Status | Notes |
|---|---|---|
| P0 Foundations | done locally (not pushed) | `pnpm verify` + `forge test` green. Not verified: CI on GitHub, `pnpm local:up` stack only (now healthy; contracts + seed not checked) |
| P1 Recorder core | P1-01…P1-19 done locally; exit demo passed | Hot path p99 3.4–3.8 ms after the checkpoint fix (S13); T9 (core ≤ 1 ms) still not met, not gated. Not verified: CI on GitHub |
| P2 Evidence store | done locally: P2-01 ✓, P2-02 ✓, P2-03 ✓, P2-04 ✓, P2-05 ✓ (memory), P2-06 ✓ (Postgres, conformance green on a local PG 16), P2-07 ✓ (part 2: HPKE + .afrkey), P2-08 ✓ (WriterQueue + ArkivStore, conformance green on Rabdi), P2-09 ✓, P2-10 ✓, P2-11 ✓, P2-12 ✓, P2-13 ✓ (API v0), P2-14 ✓, API hardening ✓ (parts 1–2), P2-15 ✓, P2-16 ✓, exit demo ✓ (Rabdi) | P2 done (DoD ✓). Not verified: CI on GitHub. Docker installed; `AFR_PG_PORT=5433 pnpm local:up` healthy (host PG holds 5432). |
| P3 Anchor + verify | in progress: P3-01 ✓, P3-02 ✓, P3-03 ✓ (Base Sepolia `0x976cf1d6…d341`, verified), P3-04 ✓, P3-05 ✓ (anvil + local PG), P3-06 ✓, P3-07 ✓, P3-08 ✓, P3-09 ✓, P3-10 ✓, P3-11 ✓ (CLI; on-chain acceptance pending: the operator signs `setAgentURI` for the demo agent) | Next: P3-12 (staging infra). The anchor-service key isn't generated or allowlisted on Base Sepolia yet. |
| P4 Watcher + dashboard | not started | |
| P5 Demo + partners | not started | |
| P6 v1 GA | not started | |
| P7 Scale & enterprise | not started | |
| P8 Network layer | not started | |

## Session entries

### 2026-11-04: P3-11 `fr agent update-registration`
- `fr agent update-registration <agentId> --out registration.json [--writer …] [--uri …] [--endpoint …]` (L5 §4.2 note).
  - It writes the registration file with exactly one `afr` entry and prints `setAgentURI` calldata plus the current operator. Nothing is signed or sent.
  - The default URI is an inline `data:` URI, so nothing has to be hosted. `--uri` (https or ipfs) means the operator uploads the file first.
- Tests (`apps/cli/test/remote.test.ts`, in-memory registry through the real `resolveAgent`):
  - the existing services are kept;
  - the calldata decodes to `setAgentURI(42, uri)`;
  - after "sending", `resolveAgent` and `fr agent show` see the `afr` service with the expected writers and anchor;
  - a rerun is idempotent;
  - bad `--uri`/`--endpoint`, a missing writer list, an existing `--out` and `local:` agents → 3.
- Acceptance ("demo agent's registration contains the afr service") still needs a real Base Sepolia agent. The operator registers it if needed, then signs the printed `setAgentURI`. Check it with `fr agent show`.
- Shortcuts: no `fr agent register`, and no fork test of the CLI itself (P3-04's fork test covers `setAgentURI`/`tokenURI` against the real registry). The profile-vs-registration writer mismatch is left to the verifier's warning.

### 2026-11-04: P3-10 `apps/cli` remote commands
- `fr verify agent`, `fr prove`, `fr agent show`, `fr keys reader new|show` (`apps/cli/src/remote.ts`), dispatched from `main`. `main` gains an optional `deps: NetDeps` (store, identity and anchor readers, passphrase) so tests run without a network.
- Exit codes per L7 §4/§5: 0/1/2, with 1 becoming 2 under `--strict`; usage or infra errors → 3. Infra errors print only their code, never the message (keyed RPC URLs). `fr journal verify` keeps its P1-16 codes.
- `@afr/verifier`, `@afr/store`, `@afr/crypto`, `@afr/identity` and `viem` 2.57.7 are now runtime deps of `@afr/cli` (workspace packages plus an existing pin; nothing new from npm).
- Tests (`apps/cli/test/remote.test.ts`, on the verifier fixtures):
  - PASS/WARN/FAIL exit codes, `--strict`, `--json`;
  - V6: identity or anchor reader throwing → 3 with no message text;
  - usage → 3;
  - `prove` output is checked independently (Merkle path, record sig, batch sig, covering checkpoint) and the command refuses to overwrite;
  - `.afrkey` is 0600, holds no passphrase, round-trips through `show`, and a short passphrase is refused.
- Shortcuts (L7 §5 note): no `keys reader import`, `--from-seq/--to-seq/--at`, `--paranoid` or `--arkiv-rpc`. `agent show` and the RPC readers are exercised only through the P3-04/P3-07 tests, not end to end on Base Sepolia.

### 2026-11-04: P3-07 … P3-09 `@afr/verifier` verifyAgent
- `verifyAgent(agentId, {store, identity, anchors?, reader?, lane?, writers?, noWriterFilter?})` per L7 §3, report per §4 (counts and epochs as decimal strings).
  - Readers: `rpcIdentityReader` (ERC-8004 via `@afr/identity`, ECDSA + ERC-1271), `staticIdentityReader` (`local:` agents), `rpcAnchorReader` (`rootOf`, `isRecorder`, block time from the anchor tx's `Anchored` log).
  - Full mode reuses `openBatch`/`epochKek`, extracted from `decryptAgent` (unchanged API).
  - Delegation validity is bounded by the anchor block time of the first covering checkpoint (≤ notAfter + 1 h); in full mode also by each record's `ts`.
  - Untrusted noise rules: L7 §3 note (doc edit).
- Anchor service: the `CheckpointStatement` domain is now the identity chain (L1 §7), not the anchor chain; leaves carry `agent_id` (not in the manifest).
- Tests (`packages/verifier/test/verify.test.ts`, fixtures from core/crypto/store only): V1 (every negative record vector sealed in a signed batch → exactly its codes; batch-level tampering → exact codes), V4 (100 forged batches: hidden by the writer filter, `IGNORED_UNSIGNED: 100` without it), V5, anchors (mismatch, bad proof by recorder vs. by anyone, unknown signing key, time bound), full mode, identity/infra (RPC error throws, never FAIL).
  - The vectors caught a crash: a float `ts` in an untrusted decrypted header (now ignored; it's already HEADER_INVALID).
- Shortcuts: depth-1 delegations only (identity-key sub-delegation, L1 §7.1, lands with that recorder mode); no `--at` / seq ranges; CT_HASH can't be produced through the store (the frame codec rejects it), so it isn't tested; profile signature checked against the current operator.
- Not verified: V2 (demo agent on testnet), against real Base.

### 2026-11-04: P3-05 `apps/anchor` + P3-06 API checkpoints → anchored
- `apps/anchor` (L5 §3):
  - `AnchorChain`: RecorderAnchor calls via a signer that is a viem Account. Locally signed tx; raw bytes and hash journaled before broadcast; inclusion is pending, unknown, dropped or reverted.
  - `validateCheckpoint`: the batch entity exists; its attrs match; the frame decodes; `batch_sig` recovers to a frame session key that the recorder announced.
  - `AnchorService.tick`: validate, then build (rewinds → BROKEN_CHAIN/EQUIVOCATION), then the manifest, then sign, journal, broadcast, then included, then `afr.checkpoint.v1` per leaf (CheckpointStatement signed by the anchor key, plus its proof), then published. After that, safe and finalized come from block tags.
  - Arkiv writes use deterministic idempotency keys and reconcile before put.
  - `PgAnchorDb`, `PgWriteJournal`.
  - `main.ts`: env wiring, an `isRecorder` check on start, and `runAsLeader` (`pg_try_advisory_lock` on a dedicated connection, tick every 30 s).
- `@afr/core`: `anchorProofs(leaves)`, one tree build for all proofs. The tick for 150 leaves went from 14 s to 1.7 s.
- API: migration v4 (checkpoint anchor columns, `anchors`, `anchor_write_journal`); `/v1/recorder/config` has `anchored` per lane. OpenAPI and the client were regenerated.
- Recorder: verified → `notified` on a delivered checkpoint notice. `pollConfig()` every 60 s marks batches ≤ the anchored `seq_to` as `anchored`.
  - `outbox.test.ts` now expects `notified` where it expected `verified` (an intended state change).
- Tests:
  - `apps/anchor/test/anchor.anvil.test.ts`: A2 (50×3 → one tx, every proof passes `verify()` on-chain, statements recover to the anchor key), A3 (rewind rejected and alerted), forged/unannounced session keys, A5 (crash after sign and at broadcast → one tx, one manifest, no duplicates).
  - New `tools/e2e` workspace package (`@afr/e2e`): apps may not import each other, so cross-app tests live here. It covers API notices → PG queue → anchor on anvil → config `anchored`, `PgWriteJournal`, and leader failover. It needs AFR_PG_URL and anvil.
  - Recorder config poll test.
- Doc edits: L3 (manifest `anchor_tx ""`/`epoch 0`, written before its tx), L5 §3.4 (real tables, statuses, no pg-boss, leader lock), L8 §3 and §4.4 (config `anchored`), L8 §5 (v0 has no queues).
- Shortcuts (marked in code):
  - Local key signer; KMS is P3-12.
  - No fee-bump replacement after 3 blocks.
  - Checkpoint entities are written one by one, not in executeBatch chunks of 20.
  - The rolling extension job and the watcher alert feed aren't implemented; alerts are only logged.
  - The delegation → operator check is left to the verifier.
  - Arkiv-scan fallback for missed notices (L5 §3.1 item 1) isn't implemented.
- Not verified: a real Base Sepolia anchor. The anchor-service key must be generated, then the admin calls `setRecorder(key, true)`.

### 2026-11-04: P3-04 `packages/identity` (ERC-8004 adapter)
- Sources: `src/abis/README.md`. Repo erc-8004/erc-8004-contracts `b9e466c` (2026-08-15) and the Base docs. Checked on-chain: proxy, version 2.0.0, deploy block (SPIKES S11).
- API (L5 §4.4):
  - `resolveAgent`, `operatorAt`, `blockAtOrBefore`, `verifyOperatorSig`, `parseRegistration`, `findAfrService`, `buildRegistrationWithAfr`, `fetchUriJson`, `encodeRegister`, `encodeSetAgentURI`, `encodeValidationResponse`.
  - Plus the ABIs and the `ERC8004_IDENTITY_REGISTRY` addresses.
  - Deps: `@afr/core`, `viem` 2.57.7.
- Deviation, with L5 §4.3 updated: `operatorAt` reads historical `ownerOf` at the last block ≤ ts instead of scanning Transfer logs. The public RPC allows 200-block log ranges, and the registry is 18M blocks old.
  - Block search is exponential back from head, then bisection. Base Sepolia block times aren't constant, and old headers are pruned on the public RPC.
- Tests:
  - 11 unit tests: registration and afr checks, URI schemes, size cap, block search on an irregular chain with pruned history, calldata round-trips, CHAIN_MISMATCH.
  - `identity.fork.test.ts` (A6 + A7) runs against the real registry on an anvil fork of Base Sepolia. It registers an agent, resolves it (afr entry, agentWallet), checks `operatorAt` before and after a transfer and before the mint, and checks that agentWallet clears on transfer. It then verifies ECDSA for the right operator per time and ERC-1271 via a mock 1271 wallet.
- Not verified:
  - A7 with a real Safe: the 1271 wallet is the test MockWallet.
  - The fork test needs `BASE_SEPOLIA_RPC_URL` and skips without it, so CI skips it unless that is set.

### 2026-11-04: P3-03 CREATE2 deploy → Base Sepolia
- `contracts/script/Deploy.s.sol`:
  - Calls the canonical CREATE2 deployer `0x4e59…956C` directly. Salt `keccak256("afr/RecorderAnchor/v1")`.
  - Idempotent: if code is already at the predicted address, nothing is sent. Fails early if a role is missing.
  - Tests in `test/Deploy.t.sol`.
  - Finding: `always_use_create_2_factory` doesn't route a `new{salt}` made from a helper contract, so the script calls the factory itself.
- `contracts/README.md` (deploy steps, env). `foundry.toml` gains the `base_sepolia` RPC alias and Etherscan v2 verification (chain 84532).
- Deployed:
  - Address: `0x976cf1d60b3dc477c70b9e649005f5a12202d341`.
  - Tx: `0xea312325811cae1fb3c9a58c38476829b680b191eeec5ab7528c9121b333073e`.
  - Block 54399317, 718,748 gas, status 1.
  - Verified on BaseScan (and submitted to Sourcify).
  - Read back: admin = isRecorder = `0x952d…35aF` (the user's wallet, testnet choice), epoch 0.
  - The deploy-only key in `.env` pays gas and has no role.
- `@afr/core` `ANCHOR_CONTRACTS` (`anchors.ts`): `{address, fromBlock, version}` per chain. New public export (P3-03 scope).
- Before mainnet: the admin should be a Safe, and the recorder the P3-05 anchor-service signer. Different roles give a different CREATE2 address.

### 2026-11-04: P3-02 `RecorderAnchor.sol` + Foundry suite (A1)
- `contracts/src/RecorderAnchor.sol`: the L5 §2 normative interface verbatim, formatted with `forge fmt`. Immutable, no receive, admin only edits the allowlist.
- `contracts/test/RecorderAnchor.t.sol` (12 tests with Smoke):
  - Unit: allowlist, NotAdmin/NotRecorder/ZeroRoot/EmptyAnchor/DuplicateRoot (including a rollup reusing a single anchor's root), events, epochs, no ETH.
  - Vector parity: reads `anchor.json` and checks every TS proof with `verify`. The single-leaf root equals `leafHash`. A forged seq_to fails.
  - Fuzz: 1–33 random leaves, a commutative-keccak tree built in the test, and `verify` against tampered lane/seq_to/chain_root/epoch.
  - Invariants: `epoch` equals successful anchors; `rootOf[epochOf[r]] == r` and each root gets one epoch. The handler also replays landed roots.
  - Gas: steady-state `anchorRoot` ≈ 56.7k execution (77.7k per tx with the 21k intrinsic, since forge runs `isolate = true`). L5 §2 now states the target excludes intrinsic gas.
- `foundry.toml`:
  - Read-only `fs_permissions` for the vectors directory.
  - Fixed fuzz seed, so `forge snapshot --check` is stable.
  - Invariant runs and depth set to 64/64, since the defaults took more than 5 minutes.
- `.gas-snapshot` regenerated.
- Next: P3-03, the CREATE2 deploy script and Base Sepolia deployment. Needs sign-off and a funded deployer key.

### 2026-11-04: P3-01 anchor tree + `anchor.json`
- `@afr/core` `merkle.ts` (L1 §6):
  - `AnchorLeaf`, `sortAnchorLeaves`, `anchorRoot`, `anchorProof` (looked up by (agent_key, lane), never by index) and `verifyAnchorProof`.
  - Leaves are `[bytes32, uint32, uint64, bytes32]`, sorted by (agent_key, lane) inside the function, so input order never matters.
  - Errors: ANCHOR_EMPTY, ANCHOR_DUPLICATE (agent_key compared case-insensitively), ANCHOR_LEAF_NOT_FOUND.
- New vector file `anchor.json` (afr/anchor v1): a single leaf, and 5 leaves over 3 agents given unsorted (lane 2³²−1, seq_to 2⁶⁴−1). Existing vector files are unchanged (gen reports 0 rewrites).
- Tests: core merkle (OZ parity, forged leaves, error codes) and vectors.test.ts recomputes `anchor.json`.
- Next: P3-02 `RecorderAnchor.sol` (needs sign-off for `contracts/`); its Foundry suite should check parity with `anchor.json`.

### 2026-11-04: P2 definition of done
- Conformance is green on memory, Postgres and Rabdi (P2-05, P2-06, P2-08).
- Cost model (Arch §12.2): measured exit-demo receipts replace the size estimates, all 30 d unless noted:

  | Entity | Size | Gas |
  |---|---|---|
  | Batch | ≈ 10 KiB | 688k–731k |
  | Delegation | 447 B | 247k |
  | Keygrant | 554 B | 211k |
  | Agent profile | 555 B, 180 d | 465k |

  The S6 formula predicts the batch within ~10%. Fixed overhead is ≈ 0.0005 tGLM per agent-month at 1 gwei before batches.
- Chaos (`packages/recorder/test/chaos.test.ts`, seeds 1/7/42):
  - 1–3 random 429/timeout/lost_response/revert failures per round, over 12 rounds, hitting delegation, profile, keygrant (real HPKE reader) and batches, plus a crash mid-submit.
  - Results: one entity per batch position, per session key and per (epoch, reader), and exactly one profile. The batches tile [0, last session_end] once the next process runs.
  - Canaries in meta, args and result are absent from every attribute and payload of every schema.
- Plaintext check on Rabdi: `exit-demo.ts` puts a fresh canary in every record, then reads back every entity of the agent. Second run: 3 batches verified, 7 entities scanned, 0 leaks. It also reconciled the write the first run left `submitting`, without a resend.
- Finding (not a bug, but it costs a round trip): `Recorder.close()` gives uploads 5 s, so its `session_end` batch, or one meeting a leftover failure, often waits for the next start. It's never lost and the next process uploads it. A configurable close drain timeout would settle it in one run (L2 §7 shutdown).
- Next: P3 (anchor + verify).

### 2026-11-04: P2-07 part 2 (HPKE keygrants, .afrkey) + P2-16 decrypt-agent
- Deps (approved): `@hpke/core` 1.9.0, `@hpke/dhkem-x25519` 1.8.0 in `@afr/crypto`, exact pins.
- `@afr/crypto`:
  - `sealKeygrant` / `openKeygrant` (L4 §5): async, using the noble-backed X25519 KEM. Open checks the kek_id.
  - `generateReaderKey`.
  - `.afrkey` `exportReaderBackup` / `importReaderBackup` (L4 §6), with argon2id from the already-installed `@noble/hashes`.
  - Tests (`keygrant.test.ts`, 7):
    - K4: the RFC 9180 A.1 vector gives the exact `enc` and `ct` bytes.
    - Seal/open round trip. A wrong reader, epoch, kek_id or agent gives HPKE_OPEN_FAILED; a lying kek_id gives KEK_ID_MISMATCH.
    - K6: backup round trip, BACKUP_PASSPHRASE on a wrong passphrase, the L4 defaults, and malformed files or swapped pubs refused.
- Recorder: `KeygrantSealer` may return a Promise, so `sealKeygrant` from `@afr/crypto` plugs into `UploadOptions.sealKeygrant`.
- `@afr/verifier` `decryptAgent({store, agentKey, lane, reader, writers?})`, the precursor of L7, which:
  - lists batches (equivocation-checked) and checks each frame, its attrs and `batch_sig`;
  - checks seq continuity, `prev_chain_root` links, `batch_root` and `chain_root`;
  - opens each epoch's keygrant (statement, `encHash` and the session-key signature checked);
  - decrypts, then runs `verifyRecords` (hash, links, signatures) and `verifyBody` (commitments).
- `tools/scripts/decrypt-agent.ts`: `keygen --out x.afrkey` and `decrypt --agent … --reader-key … [--lane] [--writer]… [--out]`.
  - Read-only Arkiv: a throwaway account with a zero spend cap.
  - Passphrase from `AFR_READER_PASSPHRASE` or a hidden prompt.
  - Plaintext only goes to `--out` (0600, never overwritten); stdout gets the summary and findings.
  - Errors print codes only, since viem errors can carry the keyed RPC URL.
- Tests (`apps/cli/test/decrypt-agent.test.ts`, 4):
  - A recorder with a configured reader goes through MemoryStore and the script: every batch decrypts with no findings, seqs are contiguous to `session_end`, the canary appears only in `--out`.
  - A stranger reader gives NO_KEYGRANT.
  - A tampered ct gives FRAME_INVALID.
  - keygen writes a 0600 file with L4 parameters and refuses weak passphrases and overwrites.
  - Smoke run against Rabdi (read-only): keygen + decrypt ran clean (0 batches for the test agent).
- shortcuts:
  - Delegation validity behind session keys, profile writers and anchors aren't checked (full verifier, P3).
  - One lane per run.
  - Records are held in memory.
  - K1 `crypto.json` vectors are still not generated.
  - The exit demo against Rabdi with a configured reader isn't run: it needs real writes (gas) and your go-ahead.
- ERC-6492 attack cases added to `apps/api/test/siwe-1271.test.ts` (6 tests now), all 401 rather than 503, with nothing deployed:
  - the intruder's own wallet deployed through the same factory while claiming the victim's address;
  - calldata the factory rejects, and a "factory" with no code;
  - a magic-suffixed wrapper that doesn't decode;
  - no `siweClient` configured.
  - Also checked: after the wallet is really deployed, plain 1271 and the wrapper both log in as the same user. No code changes were needed.
- **P2 exit demo passed (Rabdi):**
  - Ran `tools/scripts/exit-demo.ts --reader <x25519 pub>`: a dev `local:` agent with the operator key in git-ignored `.afr-demo/`, a durable fsync'd file write journal, and a 0.05 tGLM spend cap.
  - It wrote the delegation, profile, a keygrant to the reader, and 2 batches. 5 txs, all receipts `success`.
  - `decrypt-agent decrypt --reader-key reader.afrkey --writer …` then gave `ok: true`, 2 batches, 6 records (session_start, 4 tool calls, session_end) and no findings.
  - Caveat: `Recorder.close()` waits only 5 s for uploads. The session_end write was broadcast and confirmed on-chain, but the local journal still says `submitting`. The next run reconciles it without resending.
- Next: the P2 definition-of-done items (S6 cost numbers in Arch §12.2, chaos test, an automated no-plaintext-in-attributes check over the e2e run).

### 2026-11-04: apps/api hardening, part 2 (closes the remaining hardening shortcuts)
- Rate limits on Redis (`ApiOptions.redis`, ioredis 6.0.0, `skipOnError`). Redis 7.4.6 added to compose; `AFR_REDIS_URL` and `AFR_SMTP_URL` are in turbo's test env.
- `OrgSecrets` DEK cache: LRU (`maxCached`, default 1000) plus TTL (`ttlMs`, default 15 min), injectable clock, evicted keys zeroed.
- `migrateLegacySecrets({pool, secrets, legacyMasterKey})` re-seals old master-key watch keys and pre-signed revocations. Returns `{migrated, current, failed}`.
- Invitations: `GET` (pending, admin) and `DELETE /v1/orgs/{org}/invitations/{id}` (revoke, audited). Email via `smtpMailer` (nodemailer 10.1.7) after commit, link `{dashboardOrigin}/invite#token`, `email_sent` in the response.
- Auditors: migration v3 `agent_auditors` (RLS). `GET/POST/DELETE /v1/agents/{id}/auditors`. Auditors see only assigned agents (404 otherwise) and get 403 on member and invitation lists. Assignments are dropped on role change or removal.
- CORS: `@fastify/cors` 11.3.1, `dashboardOrigin` only.
- ERC-6492: `MockWallet` gained a constructor plus a `MockWalletFactory` (CREATE2). The test signs for an undeployed wallet through `serializeErc6492Signature`: login works, nothing gets deployed, and an intruder's inner signature is 401.
- OpenAPI and `packages/client` regenerated. Tests: `test/hardening.test.ts` (7: CORS, a 2-instance shared Redis budget, invitation email/list/revoke checked against Mailpit, a failing mailer, auditors, DEK LRU/TTL, legacy migration) plus the 6492 case in `siwe-1271.test.ts`.
- shortcuts: no production entry point builds the Redis and mailer clients from env yet (`buildServer` takes them injected, as with `pool`); the invitation email is plain text; `migrateLegacySecrets` is a function, not a CLI.
- Next: P2-16 (`tools/scripts/decrypt-agent.ts`).

### 2026-11-04: P2-15 mirror mode (dual-write to Postgres)
- Journal v4: `mirror_queue` (full `PutRequest`; bigint attrs tagged in JSON). `enqueueMirror`, `dueMirrors`, `deleteMirror`, `retryMirror`, `mirrorSize`.
- `putOnce(store, req, onConfirmed?)`: the callback runs once the primary confirmed (directly or by reconcile). `publishDelegations`, `publishProfile` and `publishKeygrants` take `mirror?`. `Uploader.onVerified` now also gets the batch's `PutRequest`, in the verified transaction.
- `Mirror` (`src/mirror.ts`): ordered, single-flight drain via `putOnce` + payload readback (`MIRROR_MISMATCH`), whole-mirror pause on failure, never drops. Wired from `UploadOptions.mirror`; drains on tick and at the end of `flush()`.
- Tests (`test/mirror.test.ts`, 6): delegation + profile + batches land with identical bytes; mirror down → primary still verifies, one attempt then backoff, backlog survives a restart and drains; a re-queued entity is written once; a diverged mirror is refused; config without an injected mirror logs `MIRROR_UNCONFIGURED`; canary absent from mirror payloads and attrs.
- Verify: lint, typecheck, layers and every package but the recorder green; recorder 58/59, with R2 (SIGKILL crash test) failing and vitest workers dying (once a segfault), identically on the commit before this change. Other programs segfaulted on this machine at the same time (desktop app, Chrome, a Python GPF), so it looks environmental; R2 passes alone. Re-run on a stable machine/CI before trusting it.
- shortcuts: no recorder test against a real PostgresStore (it would need `pg` as a recorder devDep; PostgresStore passes the same conformance suite as MemoryStore); stores are still injected, not built from `afr.config.yaml`; no dashboard read-fallback or rollback re-create tool yet (they read the mirror table directly); mirror copies aren't extended, same as the primary until rolling extension lands.
- Next: P2-16 (`tools/scripts/decrypt-agent.ts`).

### 2026-11-04: apps/api hardening (closes the P2-13 shortcuts)
- Deps (approved, exact): `@fastify/rate-limit` 11.2.2, `@fastify/helmet` 13.2.0, `@fastify/swagger` 9.9.3, `fastify-type-provider-zod` 7.0.0, `openapi-types` 12.1.3, `@aws-sdk/client-kms` 3.1161.0 (api); `openapi-fetch` 0.17.0 + dev `openapi-typescript` 7.13.0 (client; its peer range says TS 5, works on 6.0.3).
- Public API change (`@afr/api`): `KeyWrapper` is now an async per-org data-key wrapper (`wrapDataKey`/`unwrapDataKey`); new `kmsKeyWrapper`, `OrgSecrets`, `inOrg`/`inTx`, `openApiDocument`; `ApiOptions.siweClient`. `routes/user.ts` split into `auth.ts`, `orgs.ts`, `agents.ts` (L8 §9).
- Migration v2: `orgs.dek_wrapped`, `invitations`, `watched_addresses`, role `afr_app`, `afr_org()`, RLS policies on every tenant table. Every org-scoped route runs inside `inOrg`.
- Routes: members (list/add/role/remove, owner rules, last owner kept), invitations (create, accept), `PATCH /v1/orgs/{org}`, `PATCH /v1/agents/{id}` (name, threshold, status), watched addresses, lanes, batches and checkpoints (cursored). All routes declare Zod body/params/query/response schemas.
- SIWE: ERC-1271 / ERC-6492 through `siweClient` (viem `verifyMessage` action), only for the client's chain; RPC failure → 503, not 401. Signatures up to 8 KB.
- §7 rate limits (session 20/s, nonce + login 10/min per IP, recorder 200/4 s per key after auth, 429 `RATE_LIMITED`), §8 helmet headers.
- OpenAPI 3.1 → `packages/client/openapi.json` (drift test in `apps/api/test/openapi.test.ts`, regenerate with `AFR_UPDATE_OPENAPI=1`) → `src/schema.ts` (`pnpm --filter @afr/client generate`, drift test) → `createAfrClient` (openapi-fetch, CSRF header on mutations).
- Fixed in passing: three routes sent their response before COMMIT (invitation, recorder key, watched address); all now reply after the transaction.
- Tests: 16 API (+ RLS isolation without WHERE and RLS-refused cross-org insert, members, invitations, PATCH, watched addresses, read cursors, rate limits, headers), ERC-1271 on anvil (`AFR_ANVIL_URL`, mock wallet in `apps/api/test/fixtures`, contracts/ untouched), KMS on LocalStack (`AFR_KMS_ENDPOINT`), 3 client. Root `test` now runs `--concurrency=50%` like build/typecheck: the full suite oversubscribed 4 cores and unrelated tests timed out. `pnpm verify` green with all three env vars.
- shortcuts (all but the privacy/retention and `users` items closed by part 2 above): in-memory rate-limit counters (per instance; Redis store when the API scales out); DEK cache never evicts; no invitation list/revoke routes or email delivery; auditors see every agent (no assignment table yet); privacy/retention changes still need the signed-profile flow; `users` has no RLS (not tenant data); no CORS plugin (dashboard is same-origin for now); no ERC-6492 counterfactual test (viem handles it; needs a factory fixture); data sealed under the old single master key (only test DBs) can't be opened.
- Next: P2-15 (mirror mode), done below.

### 2026-11-04: P2-14 recorder outbox → API
- `@afr/crypto` (additive): `RECORDER_KEY_RE`, `recorderStringToSign`, `recorderSecretHash`, `signRecorderRequest`, moved from `apps/api` so the recorder and the API share one signer (the API re-exports them).
- Journal: `outbox` table + `atomically`, `enqueueNotice`, `dueNotices`, `deleteNotices`, `retryNotices`, `outboxSize`, `oldestUnverifiedBatchAt`. Notices are journaled in the same transaction as the record append (`tx_intent`), the batch `verified` update (`checkpoint`, via `Uploader.onVerified`) and `markDelegationPublished` (`delegation`).
- `Outbox` (`src/outbox.ts`): single-flight drain, intents batched ≤ 100, backoff `min(1 s·2^n, 1 h)`, 4xx (≠ 408/429) dropped and logged, 7-day expiry; heartbeat every 30 s from the tick. Wired when `api` is configured and `env[api.key_env]` is a recorder key, else `API_KEY_MISSING`.
- Tests (`test/outbox.test.ts`): signatures checked against the shared signer; delegation + checkpoint match the journal; intents batched with watch-key commitments; API down → kept with backoff, delivered after a restart in order, 400s dropped; no key → off; one heartbeat across many ticks; canary absent from all request bodies. API-side idempotency is P2-13's P5 test. Payloads checked against the API's strict schemas by hand. `pnpm verify` green with `AFR_PG_URL`.
- shortcuts: no recorder→real-API e2e test (needs `@afr/recorder` as an `apps/api` devDep); `GET /v1/recorder/config` isn't polled (`sync_readers` would rotate the epoch; readers are [] until §4.7); `msg_sign` sends no intent.
- Next: P2-15 (mirror mode).

### 2026-11-04: P2-13 apps/api v0
- Deps (approved, lean set): `fastify` 5.12.8, `@fastify/cookie` 11.1.5 (exact). Reuses `pg`, `zod`, `viem` (`viem/siwe` for EIP-4361, so no `siwe` package).
- `apps/api`: `buildServer({pool, siweDomain, keys, now?, logger?})`, `migrate(pool)` (raw SQL, advisory-locked).
  - Auth (§4.1): SIWE nonce (single-use, 10 min) → session cookie `__Host-afr` (httpOnly, Secure, SameSite=Strict, 12 h) + CSRF token (`__Host-afr-csrf` cookie, `X-CSRF-Token` on mutations); `/v1/me`, logout.
  - Orgs (§4.2): create (caller becomes owner), list, get.
  - Agents (§4.3): create, with the watch key returned once and stored wrapped (`localKeyWrapper`, AAD = agent_key); list, get; recorder keys created (shown once, only `sha256(secret)` stored) and revoked.
  - Recorder endpoints (§4.4): heartbeat, intents (≤ 100, `pg_notify('afr_intents')`), checkpoints (+ `batches_index`, lane advance), delegations (pre-signed revocation wrapped), config (ETag/304).
  - Tenancy: membership checked on every route, 404 for other orgs; writes need owner/admin/engineer; audit log on mutations. Strict Zod schemas reject unknown fields; error bodies never echo input; 5xx logged by code + route only.
- Recorder auth (§2, made exact in L8): `signRecorderRequest`/`checkRecorderRequest`; HMAC key = sha256(secret).
- Tests (`apps/api/test/api.test.ts`, needs `AFR_PG_URL`, own schema per run): SIWE + nonce reuse + CSRF; watch key wrapped, secret not stored, cross-org 404; P2 (stale > 5 min, body tamper, wrong secret, revoked key, wrong lane); P5 (duplicate checkpoint → one row, intents/delegations idempotent); config ETag; plaintext guard. Green on the compose PG; `pnpm verify` green.
- shortcuts (most closed by the hardening entry above): config `readers` is always [] until §4.7.
- Next: P2-14 (recorder outbox → API).

### 2026-11-04: P2-12 delegations + agent profile before batches
- `@afr/recorder` `statements.ts`:
  - `publishDelegations`: every signed, unpublished delegation in the journal becomes `afr.delegation.v1` (readonly, locked, permissionless extension; payload CBOR `{message, sig}`). That includes crashed sessions' delegations.
  - `publishProfile`: `afr.agent.v1` signed by the operator (`KeyManager.signAsOperator`, operator_env only). It is versioned on a content change and is mutable (not readonly, not locked, 180 d).
  - `putOnce`: the reconcile-instead-of-resend helper, now shared with keygrants.
- Uploader gate: every key in a batch's `session_keys` needs a published delegation (L2 §9). Publishing order per flush: delegations, then profile, then keygrants; each kind's failure is logged once and doesn't block the others.
- Journal v3: `session_keys.delegator`, `session_keys.delegation_entity`; `getMeta`/`setMeta`. `UploadOptions.writers` (default: the store's `writer`).
- Tests: `test/statements.test.ts` (interactive delegation held back → no entity, batch stays `prepared`; after signing, delegation precedes the batch and its EIP-712 sig verifies; crashed session's delegation published before the batch listing its key; profile sig verifies, version 1 → 2 on reader change, no republish when unchanged). Test harnesses now await `delegationReady()`; R8/crash tests gate the batch so injected failures hit it rather than a statement. Canary widened to every written entity. `pnpm verify` green.
- shortcuts: no watched-address config yet (profile `watched` is empty, `watchedHash` = keccakJcs([])); pre-v3 journal rows without a `delegator` are never published (dev journals only); a reverted statement write stays stuck under its id.
- Next: P2-13 (`apps/api` v0).

### 2026-11-04: P2-06 PostgresStore + ADR-024 batch signer
- ADR-024 (L1 §5.3/§5.4, L2 §9, L7 annotated): `batch_sig` may be made by any key in `session_keys`. The recorder signs with the latest held record key, otherwise with the current session key, which is then appended to `session_keys` with no record pointing at it. `batch_digest` and test vectors unchanged. `BATCH_UNSIGNABLE` is gone: the batcher seals every unbatched record and `sealBatches` splits at the midpoint. `SealContext.batchSigner` is new (internal).
- `@afr/store` `postgres/`: `PostgresStore` + `migratePostgres` (L3 §9 table, GIN + batch indexes, guard trigger for readonly/lock). Attribute numbers are exact jsonb numbers (read back as bigints from their source text); eq conditions use `attrs @>` (GIN), ranges compare jsonb numbers; keyset pagination on (attr, key); blocks are simulated from an injected ms clock (2 s). Deps: `pg` 8.23.1, `@types/pg` 8.23.1 (exact).
- Tests: `store/test/postgres.test.ts` runs the conformance suite (C8 skipped: no failure injection; a pg INSERT is atomic) plus trigger and 2^63 round-trip checks when `AFR_PG_URL` is set (turbo `env`). Green on the compose PG 16 (`AFR_PG_PORT=5433`). Recorder: crash-tail split test (dead-key backlog > one frame → parts signed by the new key, frames verify). Fixed an order-dependent assertion in the P2-09 `groupDuplicates` test (flaky ~1/3).
- Docker 29.1.3 + Compose 2.40 installed. Compose ports now bind 127.0.0.1 only (Docker bypasses the host firewall); the PG host port is `AFR_PG_PORT` (default 5432).
- Not done: CI Postgres service, mirror mode (P2-15).
- Next: P2-12 (delegation + agent profile before batches).

### 2026-11-04: P2-11 epoch KEK lifecycle + keygrants
- `@afr/recorder` `epochs.ts`:
  - `EpochManager`: epoch = UTC month · 16 + rotation; KEK generated by the recorder and stored sealed under the journal key (AAD kek_id), reused across restarts.
  - Rotations: month boundary, DEK-wrap budget (2^20 − 4,096, wraps counted per sealed batch), reader removed (immediate), manual (`Recorder.rotateEpoch()`). `Recorder.setReaders()`: an added reader gets a grant for the current epoch.
  - `publishKeygrants`: per missing (epoch, reader) → `sealKeygrant` (injected) → EIP-712 `KeyGrant` signed by the session key (scope bit 4) → `afr.keygrant.v1` (readonly, not locked, no permissionless extension). Lost responses and crash-time conflicts reconcile instead of resending.
  - The uploader is gated per batch on its epoch's `grants_published`; publishing runs before each drain.
- `SessionKey.signStatement` (additive): EIP-712 statements with the session key on the identity-chain domain. Journal v2 migration (uncommitted, so extended in place) adds `epochs.wraps` + `granted_json`. `UploadOptions.kek` replaced by `sealKeygrant` (the recorder owns KEKs). `@afr/store` `decodeCanonical`.
- Tests: `recorder/test/epochs.test.ts` (sealed-at-rest KEK reused across restart, month rotation 352 → 368, manual + wrap-budget rotation, keygrants before the first batch with EIP-712 sig verified, no sealer → uploads held + logged once, reader add/remove, KEK canary over the journal db/WAL, store and logs); P2-10 tests now read KEKs from the journal. `pnpm verify` green.
- **Blocked:** the real `sealKeygrant`/`openKeygrant` (L4 §5 HPKE) needs `@hpke/core` + `@hpke/dhkem-x25519` (P2-07 part 2); tests use a shape-only stand-in. Until then, configuring `encryption.readers` holds uploads back by design.
- shortcuts: a reverted keygrant write keeps its idempotency id and stays stuck (rotate to recover); keygrants expire like batches (min(retention, 30) d) and need the rolling-extension job like everything else.
- Next: P2-12 (delegation + agent profile before batches).

### 2026-11-04: P2-10 batcher + uploader
- `@afr/recorder`:
  - `seal.ts` (pure): records → BatchPublicV1 + frame (batch root, chain root, session_keys/sk, ADR-015 tx/nonce commitments shuffled, L6 flags at privacy ≥ 1, padded+deflated plaintext, `encryptBatch`, `batch_sig` by the last record's key). `sealBatches` splits near the midpoint at signable records; a single oversize record is truncated harder.
  - `batcher.ts`: close triggers (age, estimated size, 1,000 records, flush/close), greedy pre-chunking, restart-safe (unbatched = after the last batch), persists `sealed` batches + `records.batch_seq_from` in one transaction.
  - `uploader.ts`: L2 §4 state machine over an `EvidenceStore`, one batch at a time in seq order; idempotency key per (batch_id, attempt); not-sent errors retry, everything else reconciles (confirmed → readback verify, reverted → failed → re-prepare, not_sent → re-put, uncertain → wait).
  - Journal v2 migration: `writes` table = durable `WriteJournal` for the WriterQueue (synchronous=FULL per write). Batch-state methods.
  - Recorder: optional `upload: {store, kek, watchKey?, approvalThresholdCents?, canSubmit?}`; tick for age/heartbeat/retries, flushes off the capture path (setImmediate), `flush()`, bounded drain on close. `status().batches`.
- `@afr/store`: `encodeBody`/`decodeBody` (JSON-value CBOR, sorted keys); deflate at fflate's default level (level 9 was 4× slower for the same size). Parameter properties replaced by fields (Node type stripping in the R2 crash child rejected them).
- Fixes: `TxInput.value_usd_cents` type rejected the bigint/number the normaliser accepts.
- Tests: `recorder/test/batcher.test.ts`: R7 (seeded fuzz of 240 records up to ≈ 100 KiB, compressible or not → every frame ≤ 120 KiB, chain links, decrypt + headers/bodies match the journal, batch_sig recovers to a session key), privacy-1 attrs/flags, R8 (lost response / timeout / revert / 429 → one entity, attempts bumped only on revert), crash while submitting → reconcile + idempotent re-put, count/age triggers, dead-session tail batched with the new session_start. `pnpm verify` green. R5 p99 3.16 ms (no regression); T9 still fails locally (2.5–2.8 ms, same before this change, not gated).
- Not done (by design, later tickets): KEK lifecycle (P2-11, the recorder takes a `kek()` provider), delegation-first gate (P2-12, `canSubmit` hook defaults to allow), checkpoint notices (P2-14), config wiring of an Arkiv/PG store from `afr.config.yaml`.
- shortcuts: waiting uploads retry every tick without backoff; flags are per batch (an approval in a later batch doesn't clear `has_unapproved_tx`); without a watch key the commitment lists are empty.
- Resolved by ADR-024: L1 §5.3 said `batch_sig` is by the key that signed the batch's last record. After a crash with a large unbatched tail, the only held key is the new session's, so earlier split parts can't be signed (`BATCH_UNSIGNABLE`). Proposal: allow `batch_sig` by any key in `session_keys` with a valid delegation (L7 already only checks signer ∈ session_keys) — needs an ADR.
- Next: P2-11 (epoch KEK + keygrants), P2-12 (delegation + agent profile before batches).

### 2026-11-04: P2-09 listBatches + equivocation
- `@afr/store` `evidence.ts` (L3 §8): `listBatches(store, {agentKey, lane, fromSeq?, writers?, pageSize?})` keyset by seq_from with a pinned head; `groupDuplicates(batches, isValid)` → first valid batch per (lane, seq_from) + `EQUIVOCATION` for valid non-identical duplicates (identical re-creates collapse; invalid/forged ignored via the caller's L7 predicate).
- Doc fix (L3 §8): the old pseudocode advanced `next = seq_to + 1` per page, so duplicates straddling a page boundary were skipped (a hidden fork) and > 100 spam entities at one seq_from stopped the reader. Now a full page is cut at its last seq_from, which is read exhaustively with `eq`. L3 §3 helper signatures updated to the options form + `groupDuplicates`.
- Tests: `store/test/evidence.test.ts` (250 over full pages, fromSeq, boundary-straddling duplicates, 25-entity spam with pageSize 10, lane/agent isolation, equivocation grouping); conformance C5 now also checks `listBatches` (pageSize 7) against the plain query. C5 green on Rabdi (20 creates).
- shortcut (unchanged): ArkivStore ignores `atBlock` (SDK 1.0.1 exposes no pin), so entities created mid-listing may appear.
- Next: P2-10 (batcher + uploader), P2-12 (delegation + agent profile before batches).

### 2026-11-04: P2-04 batch frame
- `@afr/store` `frame.ts` (L3 §4): `encodeFrame`/`decodeFrame`, `packPlaintext`/`unpackPlaintext`, `pad`/`unpad`, `encodeCanonical`.
  - Deterministic CBOR via cbor-x (`useRecords:false, mapsAsObjects, variableMapSize, tagUint8Array:false`) plus our own RFC 8949 §4.2.1 key sort. cbor-x encodes ints > 2³²−1 as float64, so floats, negatives and ints > uint32 are rejected (`FRAME_INVALID`); u64 stays decimal strings.
  - `decodeFrame` validates `pub` against `BatchPublicV1Schema`, checks `payload_ct_hash = keccak256(ct)` and rejects non-canonical encodings (re-encode must match byte for byte). `FRAME_TOO_LARGE` above `BATCH_MAX_FRAME_BYTES` on both sides.
  - shortcut: fflate sync inflate has no output cap; the 64× frame-size check runs after inflating.
- Deps (approved): `cbor-x` 1.6.8 (not the 2-day-old 1.6.9), `fflate` 0.8.3, exact pins; `cbor-extract` native build denied in `allowBuilds` (pure-JS path).
- Bug fix in core: `U64Schema.safeParse(";0")` threw `SyntaxError` (zod runs `.refine` after a failed regex; `BigInt` threw). The refine now re-checks digits first. Accepted set unchanged, no vector impact. Found by the frame fuzz test; regression test in `core/test/record.test.ts`.
- Tests: `store/test/frame.test.ts` (round-trip, key-order determinism, bucket property, max-size property, fuzzed/mutated input → typed errors only). `pnpm verify` green.
- Next: P2-09 (keyset + equivocation), P2-10 (batcher + uploader, first frame caller).

### 2026-11-04: P2-01 spikes, P2-02 docs, P2-03, P2-05, P2-08
- **P2-01:** spikes S1–S10 ran on Rabdi with SDK 1.0.1. Scripts are in `tools/spikes/` (guarded writer `guard.ts`; public tx hashes journaled in `journal.ndjson`). Results are in SPIKES.md. Key findings:
  - S3: lock in one batch works.
  - S4: the SDK has no public encoder; we intercept `eth_sendTransaction` instead.
  - S5: real limit ≈ 124 KiB frame (RPC request size); 120 KiB is kept.
  - S6: **max lifetime 182.5 d**, gas ∝ bytes × lifetime.
  - S9: permissionless extension of locked entities works.
  - S7/S8: scaled to 1k entities; no rate limit hit.
  - S10: 2,111/2,111 events over 1 h, 0 missed.
  - Spend: ≈ 0.27 tGLM of 10.
- **P2-02:** spike results propagated:
  - L3 §2, §4, §5, §6, §7, §11, §13.
  - ADR-011 and ADR-012 confirmed. **ADR-013 amended:** rolling expiry by default, upfront only for retention ≤ 30 d, because no entity can outlive 182.5 d.
  - Arch §7.1, Arkiv facts and §12.2 (measured costs).
  - L2 config example; L8 `expiry_strategy` default.
  - Recorder config `store.arkiv.expiry` default `upfront` → `rolling`.
  - No name mapping (`names.ts` dropped).
- **P2-03:** `@afr/store` gains:
  - `schemas.ts`: one spec drives both the SDK `defineSchema` objects and the portable `AttrsOf<S>` types; a test parses L3 §5 and asserts exact parity.
  - `privacy.ts`: allowlists, attribute validation, `validatePut`.
  - `types.ts`: §3 interface plus `StoreErrorCode`.
- **P2-05:** `MemoryStore` + `MemoryChain`:
  - Readonly, lock, permissionless extension, the `MAX_LIFETIME` cap and a block clock.
  - `failNext` with timeout, revert, lost_response and 429.
  - Conformance suite `test/conformance.ts` C1–C10 is green on memory.
- **P2-08:** `arkiv/writer-queue.ts` + `arkiv/store.ts` + `client.ts` + `errors.ts`.
  - Write-safety bounds: gas = max(floor, 2·est), ≤ half block; fresh nonce and gasPrice; spend cap.
  - The hash is journaled before broadcast. Reconcile rebroadcasts the same bytes, or returns `uncertain` if the nonce was consumed.
  - Engine reverts are decoded via `eth_call` into typed codes.
  - 6 anvil tests use a STOP stub at the registry.
  - **Rabdi conformance:** C1–C7, C9, C10 green (`ARKIV_E2E=1`, c5Count 20); C8 runs on memory only.
  - Bugs found and fixed: viem `custom` transport retries would have re-signed (now `retryCount: 0` plus a once-per-run guard); `process.loadEnvFile` segfaults in vitest workers (now `util.parseEnv`).
  - shortcut: ArkivStore.query pages by offset without a block pin (SDK exposes none); keyset/equivocation is P2-09.
- **Deps:** `@afr/store` → `@arkiv-network/sdk` 1.0.1 and `viem` 2.57.7. Root dev: `@arkiv-network/sdk` and `viem`, for spikes. Both were already pinned in the repo.
- **Tests:** store 24 (+10 Arkiv e2e). `pnpm verify` green. One run under load (avg ≈ 6.8) had timing flakes in proxy/core/recorder tests that passed on rerun and in isolation.
- **Decisions needed:**
  - Approve the HPKE deps (P2-07 part 2). (`cbor-x` + `fflate` approved; P2-04 done.)
  - Sign off on the ADR-013 amendment.
  - Postgres for P2-06 needs Docker or a local PG.
- **Next:** P2-04 once deps are approved, then P2-09 (keyset + equivocation) and P2-10 (batcher + uploader).

### 2026-11-04 — P1 close-out check, P2-07 part 1 (crypto without new deps)
- P1 status: all 19 tickets done, exit demo passed. Open against the phase DoD: T9 (≤ 1 ms, P1-09) not met; "all tests pass in CI" unverified (no remote); demo screen recording not made (operator task).
- Done: `@afr/crypto` split into `aes.ts` / `batch.ts` / `watch.ts`. L4 §3 `batchAad`, `encryptBatch`, `decryptBatch` (KEK_ID_MISMATCH → AAD_MISMATCH → DECRYPT_FAILED); §4 `kekIdFor`, `newEpochKek`, DEK wrap (60 B), `KEK_MAX_WRAPS = 2^20`; §10 `txCommit`, `userOpCommit`, `nonceCommit`; `sealAtRest` / `openAtRest`. Error code `KEY_INVALID` renamed to the spec's `INVALID_KEY`. Noble only (sync, isomorphic, no Node built-ins); WebCrypto not used because its AES-GCM is async-only.
- Tests: crypto 11 — layouts cross-checked against ethers' ABI coder and node:crypto AES-GCM/HMAC, K2, K3, wrong KEK, K9 (15 malformed inputs → typed errors), K10. `pnpm verify` green.
- Proposed doc edits / decisions needed: (1) `AFR_KEK_ID_V1` (L4 §4, normative) is missing from the Arch §21 registry and core `DOMAIN`; kept local in `batch.ts` until an ADR adds it. (2) K1 vectors (`crypto.json`) deferred: they include keygrant `enc‖ct`, and generating them in `packages/test-vectors` needs that package allowed to import `@afr/crypto` (layer map, Arch §3). L4 §12 updated to the implemented signatures.
- Blocked: P2-01 spikes (no `.env` with `ARKIV_ACCESS_KEY` / `AFR_ARKIV_WRITER_KEY`); P2-02/03/04 depend on spike results. P2-07 part 2 (keygrants §5, reader backups §6) needs `@hpke/core` + `@hpke/dhkem-x25519` and `hash-wasm` (or `@noble/hashes` argon2id, already installed).
- Next: P2-07 part 2 once deps are approved; P2-01 once Arkiv credentials exist.

### 2026-11-04 — P1 hot path
- Done: found the R5 tail — WAL auto-checkpoint inside the insert (~20 ms every ~220 captures). Journal now disables auto-checkpoint and checkpoints (PASSIVE, 1 s) from a worker-thread connection, with fallback to auto-checkpoint if the worker exits; body sealing uses native AES-256-GCM (format unchanged, read path still noble, so every body read cross-checks it).
- Tests: new journal test that the WAL stays bounded (fails when the checkpointer is stalled). R5 p99 3.4 / 3.5 / 3.8 ms (was 4.4–6.1). `pnpm verify` green; exit demo rerun green (round trip p99 20 ms, was 84).
- Open issues: T9 unchanged (~2.8 ms vs 1 ms; signing + keccak in pure JS). No 10 % regression baseline yet. Still no git commit.

### 2026-11-03 — P1-15 … P1-19 (HTTP proxy, CLIs, SDK, bench, canary)
- Done: `apps/proxy` — Streamable HTTP downstream (`http.ts`: per-session server transport + upstream, shared chain, `/mcp` only, 4 MiB body cap, DNS-rebinding protection on loopback, bearer auth with `timingSafeEqual`, non-loopback bind refused without a token) and HTTP upstream (`Authorization` forwarded only with `forward_auth`); CLI rewritten into `init` / `run` (`--listen stdio|host:port`, `--upstream` | `--upstream-url`, interactive delegation via file requester) / `status` / `delegate` (`--sig`, `--sign`). Config: `proxy.auth_token_env`. `apps/cli`: `fr journal verify [--config | --journal]` (defaults to the fr-proxy dev identity), JSON report, exit 0/1/2. `packages/sdk`: `createRecorder`, `wrapWalletClient` (local accounts re-wrapped with `toAccount`: `tx_sign` with hash after signing, `msg_sign` before signing with `kind` personal/typed + `primary_type`/`verifying_contract`; transport wrapper: `tx_broadcast`, JSON-RPC accounts via `eth_sendTransaction`/`personal_sign`/`eth_signTypedData_v4`), `wrapAnthropic` (structural type, no SDK dependency; `create` + `stream`, original APIPromise returned), `wrapTool`, `note`, fail-open capture. Recorder R5 bench + CI gate; CI test job installs Foundry for R6.
- Tests: proxy 18 (HTTP deep-equal vs direct, two sessions one chain, auth 401/forwarding, 404, bind rule, commands incl. interactive delegation handshake, CLI HTTP spawn + SIGTERM, **R10 across the CLI**: trace-level stderr and every file under the data dir canary-free); cli 4; sdk 9 incl. **R6 on local anvil** (send/deploy/write/signTypedData/signMessage; `tx_sign.tx_hash` == mined hash; JSON-RPC account path). R5: p99 4.4–6.1 ms here (S13).
- Fixes along the way: `vitest.bench.config.ts` appended to the unit-test `include` (bench ran every test) — now overrides it; `pnpm-workspace.yaml` `allowBuilds.better-sqlite3` placeholder left by pnpm 12 set to `true` (install failed otherwise).
- Decisions / deviations: CLIs use `node:util` `parseArgs`, not commander (L2 §16 prompt) — no new dependency. L2 §11 documents `proxy.auth_token_env`. `wrapAnthropic` throws `CAPTURE_MODE_UNSUPPORTED` for `capture.context` hash_only/last_turn (recorder has no committed-but-omitted context yet) rather than recording more than configured. Not implemented (shortcut comments in code): `create({stream:true})` not recorded (warns; `messages.stream()` is), tx intent outbox + nonce commitment (P2), raw txs signed outside the wrapped client, `signAuthorization`, `wrapOpenAI`/`aiSdkModel`/framework adapters, 10 % regression baseline for the bench.
- Open issues: R5 has almost no headroom on this box; if CI flakes, options are a native signer (S13) or a faster AES-GCM in the journal. T9 still fails locally and is not gated — needs a decision (raise the target or ship the native signer). Phase exit demo against `npx @modelcontextprotocol/server-everything` still not run (npm download). Still no git commit.
- **Exit demo (2026-11-03), `apps/proxy/scripts/exit-demo.ts`** against `@modelcontextprotocol/server-everything@2.1.0` (npx, install scripts off; the package declares node ≥ 24, ran fine on 22.23): 16 tools listed; 100 `echo` calls → 203 records, `fr journal verify` ok; proxy round trip p50 7.9 ms / p99 84 ms (includes npx server). kill -9 of fr-proxy with a call in flight → restart → 10 more calls → 268 records, seq 0..267 contiguous, 3 sessions, verify ok, no findings. Hot path (R5 bench) p99 5.4 / 4.6 / 4.4 ms over 3 runs at load avg ≈ 4 — the < 5 ms criterion is met only on 2 of 3 runs here.
- Next: decide R5/T9 headroom (native signer?), then P2.

### 2026-11-02 — P1-10 … P1-14 (recorder + stdio proxy)
- Done: `@afr/recorder` — `config.ts` (zod schema of L2 §11 with defaults, strict keys, `AFR_<PATH>` env overrides with type coercion, readable multi-line errors, `configHash`); `journal.ts` (better-sqlite3, WAL, 0600, schema v1 + migration runner, agent/lane guard, one-txn appends, at-rest AES-256-GCM bodies bound to seq+hash); `keystore.ts` (dev-plaintext journal key); `keys.ts` (in-memory session keys, EIP-712 delegations: `operator_env` and `interactive` via file requester, digest known before signing); `recorder.ts` (sync `capture()`, normalisation, binary-content hashing, fail-open gap reservation → signed `gap` record, fail-closed throw, tail verification on start, `recovered_from_seq`, rotation with `session_end{rotate}` → `session_start`). `@afr/crypto`: sync AES-256-GCM. `apps/proxy`: message-level proxy (`tool_call`/`tool_result`, cancellation, upstream-close errors, `mcp_initialize` note), stdio transports, `fr-proxy run --upstream` with dev quick mode. Core: `verifyLinks` accepts well-formed gap records (`GAP` info). `tools/ts/register.mjs` runs TS sources in child processes.
- Tests: recorder 25 (R1 10k concurrent captures; R11 rotation; gaps; fail-closed; restart; canary not in journal file), **R2: 100 SIGKILL runs passed** (425 s on this box; unit suite defaults to 20, CI sets 100); proxy 5 (R3 deep-equal vs direct incl. errors and unknown tool, R4 progress/cancel/server→client, R10 log canary, stdio e2e: 100 calls → ≥ 200 records, chain verifies). `pnpm verify` green.
- Decisions / deviations (docs updated): L2 §3.2 gap shape made exact; L2 §4 journal body = JSON (not CBOR — internal, unhashed; avoids a dependency) with journal-internal AAD `AFR_JOURNAL_V1`; next_seq/prev_hash derived from `records`; L2 §5.2 initialize → `note`. Vectors regenerated before first commit so the `gap` vector has the correct shape (seq 7 covering 6). Not implemented yet (explicit errors): `delegation.mode` kms/identity_key, keystores other than dev-plaintext.
- Open issues: exit demo against `npx @modelcontextprotocol/server-everything` not run (needs an npm download; reference server fixture used instead). R2 at 100 runs adds ~4–7 min to CI; consider moving to nightly. Dependencies added: better-sqlite3 13.0.3 (native, allow-listed in pnpm-workspace), yaml 2.9.1, @noble/ciphers 2.4.0, @modelcontextprotocol/sdk 1.32.1, zod in recorder/proxy. Still no git commit.
- Next: P1-15 (Streamable HTTP), P1-16 (CLI `init`/`status`/`delegate`/`journal verify`), P1-17 (SDK wrappers, needs Anvil → Docker), P1-18 (bench gate), P1-19 (proxy canary across the CLI).

### 2026-11-02 — P1-01 … P1-09 (format and crypto core)
- Done: `@afr/core` — constants (Arch §21) + lock address; ids (`parseAgentId`, `agentKey`, `batchId`, `epochIdFor`); `jcs`/`jcsData` with guards; `commit`; Zod schemas (strict, per-type required fields, meta limits) + derived types; `buildHeader`/`validateHeader`/`hashHeader`/`buildBody` (truncation, redaction pass-through)/`commitmentsFor`; sync noble `localSigner` (byte-identical to viem `signMessage({raw})`); batch Merkle (OZ StandardMerkleTree), `chainRoot`, `batchDigest`; EIP-712 types for all 9 statements + `hashTyped`/`verifyTyped`; `verifyLinks`/`verifyRecords`/`verifyBody` with L7 codes. 76 core tests (T1–T5, T7, T8; T3/T4 at 10k runs). `@afr/test-vectors`: atomic, immutability-checking generator, 9 vector files (58 cases incl. 10 negative), `vectors.test.ts` recomputes all (49 tests). `pnpm verify` green.
- Decisions: S14 (two JCS modes, NFC kept), S15 (`epoch_id` always `month*16+rotation`), S16 (commitment has the `0x00` separator). `buildBody` returns `{ body, commit }` because commitments cover the untruncated value. `verifyLinks` resyncs after an invalid header instead of cascading SEQ_GAP/CHAIN_BREAK. T9 moved to `pnpm bench` (runs alone).
- Deviations from docs (+ doc edits made): L1 §2.2, §3.5, §9, §10; Arch §8; ADR-003 rule text. `vectors.test.ts` lives in `packages/test-vectors` (core may not import other packages). `anchor.json` and anchor trees deferred to P3 (phase says "L1 all except anchors"); done in P3-01.
- Open issues: **T9 not met here**: p99 ≈ 2.8 ms (sign ≈ 1 ms on this loaded box), see S13. Fixture registry address in vectors is a made-up test value. Dependencies added: viem 2.57.7, @noble/curves+hashes 2.4.0, canonicalize 5.1.0, @openzeppelin/merkle-tree 1.0.8, zod 4.6.7 (runtime); fast-check 4.10.2, ethers 6.17.0 (test). Still no git commit.
- Next: P1-10 … P1-13 (config, journal, keys, sequencer) — needs better-sqlite3 (native build) and `yaml`.

### 2026-11-01 — P0-01 … P0-12
- Done: pnpm/Turborepo/Biome/TS 6 monorepo; 11 packages + 9 apps with exports maps (`@afr/source` condition → `src/` in dev, `dist/` when published) and smoke tests; dependency-cruiser layer rules (proved with 4 deliberate bad imports: packages→apps, apps→apps, crypto→store, core→`node:fs`); changesets; Foundry in `contracts/` with OZ 5.6.1 + forge-std from the pnpm lockfile (no git submodules) and a gas snapshot; `@afr/test-vectors` skeleton + shape check + CI immutability check; compose stack (postgres 16, anvil, mailpit, localstack; tags verified on registries); `ci.yml` + `security.yml`; `@afr/log` (pino redaction + canary helper, tested); JSON.stringify ban script; LICENSE (Apache-2.0), LICENSE-APPS.md, SECURITY.md, CONTRIBUTING.md, PR template, README.
- Decisions: tool versions pinned to releases ≥ 2 weeks old (TS 6.0.3, not the TS 7 native port, for dependency-cruiser compatibility). `packages/core` typechecks with `types: []` so Node built-ins don't resolve. Turbo typecheck/build run at `--concurrency=50%`: `tsc` segfaulted (exit 139) with 20 in parallel on a 4-core box.
- Deviations from docs: root script is `pnpm verify`, not `pnpm ci` (pnpm 12 has a built-in `ci` = clean install). P0 doc and CONTRIBUTING updated. P0-09 is a no-op: docs and CLAUDE.md already live at the repo root.
- Open issues: no git commit or GitHub remote yet; CI and `pnpm local:up` unverified. `LICENSE-APPS.md` needs the owner's legal entity name. GitHub Actions are pinned to major tags, not SHAs (Renovate/pinning is L11 follow-up). `apps/dashboard` is a plain TS stub until P4 adds Next.js.
- Next: P1-01 (JCS + hashing in `@afr/core`).

<!--
### YYYY-MM-DD — <task IDs>
- Done:
- Decisions (link ADR/SPIKES row):
- Deviations from docs (+ doc PR):
- Open issues:
- Next:
-->
