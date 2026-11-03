# Phase P1 — Recorder Core (weeks 1–2)

**Goal:** an MCP proxy that forwards one upstream server unchanged and produces a valid, signed, hash-chained, crash-safe local journal. Plus the canonical format with golden vectors. **No network storage yet.**

| | |
|---|---|
| Entry | P0 exit criteria met |
| Exit (demo) | `fr-proxy run --upstream "npx -y @modelcontextprotocol/server-everything"` behind Claude Code (or any MCP client). 100 tool calls → journal with 200+ records. `fr journal verify` (local) passes. Kill -9 mid-run → restart → chain continues. Hot path p99 < 5 ms |
| Layers | L1 (all except anchors), L2 (pipeline, journal, keys dev-mode, proxy stdio + HTTP, SDK wallet + model wrappers) |
| Requirements | CAP-01, CAP-02, CAP-04, CAP-05, CAP-06, CAP-10, CAP-11, INT-01…INT-06, INT-08 |

---

## Week 1 — format and crypto core

| ID | Task | Ref | Done when |
|---|---|---|---|
| P1-01 | `constants.ts`, `ids.ts` (`parseAgentId`, `agentKey`, `epochIdFor`), lock address | L1 §2, §8; Arch §21 | Unit tests |
| P1-02 | `jcs.ts` with guards | L1 §3.5 | RFC 8785 vectors pass (T1, T2) |
| P1-03 | Record types + Zod schemas incl. per-type required fields | L1 §3.1–3.2 | T8 |
| P1-04 | `commit()`, `buildBody` (truncation, redaction placeholders), `buildHeader`, `hashHeader` | L1 §3.3–3.4 | |
| P1-05 | `sign.ts` (sync noble signing for the hot path, viem recovery for verify) | L1 §3.4 | Signatures recover with viem |
| P1-06 | `merkle.ts` (batch tree), `chain.ts` (chainRoot, batchDigest) | L1 §5 | T5 |
| P1-07 | EIP-712 types + helpers (Delegation, Revocation, AgentProfile, ReaderKey, KeyGrant) | L1 §7 | T7 |
| P1-08 | Test-vector generator + `vectors.test.ts` + negative vectors (records/chain) | L1 §11 | Vectors committed |
| P1-09 | Property tests T3, T4 + micro-bench T9 | L1 §12 | ≤ 1 ms p99 |

## Week 2 — recorder + proxy + SDK

| ID | Task | Ref | Done when |
|---|---|---|---|
| P1-10 | `config.ts` (zod for `afr.config.yaml`, env overrides, config hash) | L2 §11 | Invalid configs give readable errors |
| P1-11 | `journal.ts` (SQLite schema, WAL, migrations, at-rest body sealing with a dev key) | L2 §4 | |
| P1-12 | `keys.ts`: session key generation, `operator_env` + `interactive` delegation, rotation timer | L2 §7 | R11 (without publishing) |
| P1-13 | `sequencer.ts` synchronous `capture()` incl. gap handling | L2 §3 | R1, R2 |
| P1-14 | `apps/proxy` stdio↔stdio message proxy | L2 §5.2 | R3, R4 |
| P1-15 | Streamable HTTP downstream/upstream + bind/auth rules | L2 §5.1–5.2 | Works with an HTTP MCP server |
| P1-16 | CLI: `init`, `run`, `status`, `delegate` + local `fr journal verify` (walks the SQLite chain) | L2 §5.3 | |
| P1-17 | `packages/sdk`: `createRecorder`, `wrapWalletClient` (account + transport wrapping), `wrapAnthropic`, `wrapTool` | L2 §6 | R6 on Anvil |
| P1-18 | Hot-path benchmark harness (`pnpm bench`) + CI gate | Arch §12.1 | R5 |
| P1-19 | Log canary test across the proxy | L2 R10 | |

## Definition of done (phase)

- [ ] All T- and R-tests listed above pass in CI.
- [ ] `docs/04-vibecoding/SPIKES.md` updated with any format decisions that changed during implementation. If any changed, update L1 and regenerate vectors.
- [ ] Demo recorded (screen capture) for the investor update.

## Vibecoding script

1. "Read CLAUDE.md, L1 fully, and this phase doc. Do P1-01 to P1-03. Stop and show tests."
2. "Do P1-04 to P1-06."
3. "Do P1-07 and P1-08 (vectors). Print the vector files' summary."
4. "Do P1-09. Report benchmark numbers."
5. "Read L2 §2–§4, §7, §11. Do P1-10 to P1-13 including the SIGKILL crash test."
6. "Read L2 §5. Do P1-14, then P1-15."
7. "Do P1-16 and P1-17 (start Anvil via the compose stack for R6)."
8. "Do P1-18 and P1-19. Then run the phase exit demo and write a short report in `docs/04-vibecoding/PROGRESS.md`."

## Risks

| Risk | Mitigation |
|---|---|
| MCP SDK transport API differences between versions | Pin the version. Wrap transports in `apps/proxy/src/transport.ts` |
| Sync signing perf in Node | noble secp256k1 sign ~0.2–0.5 ms. Precompute. Measure early (P1-05) |
| better-sqlite3 native build issues (Alpine/Bun) | Use `node:22-bookworm-slim` images. Use `bun:sqlite` adapter for Bun |
