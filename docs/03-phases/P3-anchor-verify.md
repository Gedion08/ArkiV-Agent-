# Phase P3 — Anchoring on Base & `fr verify` (weeks 5–6)

**Goal:** checkpoint roots are anchored on Base Sepolia in rolled-up transactions, the agent's ERC-8004 registration points to its log, and an open-source CLI verifies everything end to end from public data only.

| | |
|---|---|
| Entry | P2 exit met |
| Exit (demo) | `npx @afr/cli verify agent eip155:84532:0x…:7` → PASS (structural). With `--reader-key` → PASS (full). Corrupt one frame in a local mirror and verify against it → FAIL at the right seq. Anchors visible on BaseScan |
| Layers | L5 (contract, anchor service, identity adapter), L7 (verifier structural + full, CLI), L1 §6 (anchor leaves), L11 (staging infra) |
| Requirements | ANC-01…ANC-04, VER-01…VER-04, VER-06 |

---

## Week 5 — contract + anchor service

| ID | Task | Ref | Done when |
|---|---|---|---|
| P3-01 | Anchor leaf/tree functions in core + `anchor.json` vectors | L1 §6 | |
| P3-02 | `RecorderAnchor.sol` + full Foundry suite incl. vector parity | L5 §2 | A1 |
| P3-03 | Deploy script (CREATE2) → Base Sepolia. Address in `anchors.ts` | L5 §2 | Verified on BaseScan |
| P3-04 | `packages/identity`: fetch current ERC-8004 ABIs/addresses + registration schema (document sources), `resolveAgent`, `operatorAt`, `verifyOperatorSig` | L5 §4 | A6, A7 |
| P3-05 | `apps/anchor`: loop, leader lock, signer abstraction (local key now, KMS later), manifest + checkpoint entities, status tracking | L5 §3 | A2, A3, A5 |
| P3-06 | API: checkpoint validation → queue → anchored notifications. Recorder marks batches `anchored` | L8 §5 | |

## Week 6 — verifier + CLI

| ID | Task | Ref | Done when |
|---|---|---|---|
| P3-07 | `@afr/verifier` structural mode over injected readers | L7 §3 | V1, V4, V5 |
| P3-08 | Full mode (keygrants → decrypt → per-record checks) | L7 §3 | |
| P3-09 | Anchor verification against Base (`rootOf` + proof) and unanchored-tail reporting | L7 §3 step 4 | |
| P3-10 | `apps/cli`: `fr verify agent`, `fr prove`, `fr keys reader`, `fr agent show`, JSON + human output, exit codes | L7 §5 | V6 |
| P3-11 | ERC-8004 registration update flow (CLI `fr agent update-registration` produces JSON + calldata) | L5 §4.2 | Demo agent's registration contains the `afr` service |
| P3-12 | Staging infra (Terraform: network, rds, ecs for api + anchor, kms for anchor key). KMS signer in the anchor service | L11 §2, L5 §3.3 | A4. Staging anchors from a KMS key |
| P3-13 | Nightly `testnet-e2e.yml` (P2 demo + anchors + verify) | L11 §3 | Green for 3 nights |

## Definition of done

- [ ] Verifier README with "verify an agent in 60 seconds" instructions. Published to npm with provenance (`@afr/cli@0.x`).
  - The README is done (`apps/cli/README.md`).
  - Shipped as GitHub Release tarballs (`npx` on the release URL) with `SHA256SUMS`, without provenance.
  - `release-cli.yml` (npm + provenance) waits on GitHub Actions, which is locked by a billing issue, and on an `@afr` npm org.
- [x] Spec docs (L1/L4/L7) frozen as **format v1-rc**. Any change after this needs an ADR. (ADR-025, 2026-11-05)
- [ ] A third person (not the implementer) verifies the demo agent using only the README.

## Vibecoding script

1. "Read L1 §6 and L5 §2. Do P3-01 to P3-03."
2. "Read L5 §4. Do P3-04. First search for and record the current ERC-8004 registry addresses and ABIs, citing sources in `packages/identity/src/abis/README.md`."
3. "Read L5 §3. Do P3-05 and P3-06."
4. "Read L7 fully. Do P3-07 to P3-09."
5. "Do P3-10 and P3-11."
6. "Read L11 §2–§4. Do P3-12 and P3-13."

## Risks

| Risk | Mitigation |
|---|---|
| ERC-8004 deployments/ABIs differ from the docs | Adapter isolation. Mock registries for local |
| KMS signature format pitfalls (DER, low-s, v) | Unit tests with known vectors. LocalStack |
| Verifier speed on long histories | Incremental cursors (used by the watcher and dashboard). Parallel batch fetch |
