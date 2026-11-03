# Progress Log

Update at the end of every coding session (see VIBECODING §2). Newest entries first.

## Status board

| Phase | Status | Notes |
|---|---|---|
| P0 Foundations | done locally (not pushed) | `pnpm verify` + `forge test` green. Not verified: CI on GitHub, `pnpm local:up` (Docker not installed on dev box) |
| P1 Recorder core | P1-01…P1-19 done locally; exit demo passed | Hot path p99 3.4–3.8 ms after the checkpoint fix (S13); T9 (core ≤ 1 ms) still not met, not gated. Not verified: CI on GitHub |
| P2 Evidence store | not started | |
| P3 Anchor + verify | not started | |
| P4 Watcher + dashboard | not started | |
| P5 Demo + partners | not started | |
| P6 v1 GA | not started | |
| P7 Scale & enterprise | not started | |
| P8 Network layer | not started | |

## Session entries

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
- Deviations from docs (+ doc edits made): L1 §2.2, §3.5, §9, §10; Arch §8; ADR-003 rule text. `vectors.test.ts` lives in `packages/test-vectors` (core may not import other packages). `anchor.json` and anchor trees deferred to P3 (phase says "L1 all except anchors").
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
