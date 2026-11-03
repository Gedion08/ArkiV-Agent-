# Agent Flight Recorder — Documentation

> A flight recorder for AI agents that move money. Every action is logged, signed and verifiable by third parties. Records live on **Arkiv**, roots are anchored on **Base**, identity comes from **ERC-8004**, and a chain watcher catches anything the agent did off the record.

## Start here

1. **[Product Specification (PRD)](00-product/PRD.md)**: problem, users, requirements (with IDs), pricing, GTM, risks, pitch.
2. **[Architecture Design Document](01-architecture/ARCHITECTURE.md)**: components, trust boundaries, data flows, normative crypto, constants, stack, repo layout.
3. **[Architecture Decision Records](01-architecture/ADRS.md)**: 23 decisions and why.

## Layer specs (build references)

| Layer | Doc | Package(s) |
|---|---|---|
| L1 | [Record format & crypto core](02-layers/L1-record-format-and-crypto.md) **[normative]** | `@afr/core`, `test-vectors` |
| L2 | [Capture & recorder (MCP proxy, SDK, journal)](02-layers/L2-capture-recorder.md) | `@afr/recorder`, `fr-proxy`, `@afr/sdk` |
| L3 | [Evidence store & Arkiv](02-layers/L3-evidence-store-arkiv.md) | `@afr/store` |
| L4 | [Encryption & access control](02-layers/L4-encryption-access.md) **[normative]** | `@afr/crypto` |
| L5 | [Anchoring (Base) & identity (ERC-8004)](02-layers/L5-anchoring-identity.md) | `contracts/`, `apps/anchor`, `@afr/identity` |
| L6 | [Chain watcher & alerts](02-layers/L6-chain-watcher.md) | `apps/watcher` |
| L7 | [Verifier & evidence packs](02-layers/L7-verifier-evidence-packs.md) **[normative results]** | `@afr/verifier`, `fr` CLI |
| L8 | [Platform API, tenancy, notifications, billing](02-layers/L8-platform-api.md) | `apps/api` |
| L9 | [Dashboard](02-layers/L9-dashboard.md) | `apps/dashboard` |
| L10 | [Guardrails & approvals](02-layers/L10-guardrails-approvals.md) | `@afr/policy`, `apps/approvals` |
| L11 | [Infra, DevOps & security ops](02-layers/L11-infra-devops-security.md) | `infra/`, CI |

## Phase plans (what to build, in order)

| Phase | Weeks | Doc | Outcome |
|---|---|---|---|
| P0 | 0.5 | [Foundations](03-phases/P0-foundations.md) | Monorepo, CI, layer rules |
| P1 | 1–2 | [Recorder core](03-phases/P1-recorder-core.md) | Signed hash-chained journal behind an MCP proxy |
| P2 | 3–4 | [Evidence store](03-phases/P2-evidence-store.md) | Encrypted, locked batches on Arkiv + Postgres fallback |
| P3 | 5–6 | [Anchor + verify](03-phases/P3-anchor-verify.md) | Base anchors, ERC-8004 link, `fr verify` |
| P4 | 7–8 | [Watcher + dashboard](03-phases/P4-watcher-dashboard.md) | Unlogged-tx alerts, timeline, replay |
| P5 | 9–10 | [Demo + design partners](03-phases/P5-demo-design-partners.md) | Pitch demo, mainnet anchors, 2 partners |
| P6 | 11–22 | [v1 GA](03-phases/P6-v1-ga.md) | Guardrails, approvals, auditor access, packs, billing |
| P7 | 23–40 | [Scale & enterprise](03-phases/P7-scale-enterprise.md) | Self-host, Solana, SSO, SOC 2 |
| P8 | 40+ | [Network layer](03-phases/P8-network-layer.md) | Reputation, underwriting, validation market |

**MVP = P0–P5** (≈ 10 weeks, one engineer): MCP proxy, hash chain, Arkiv writes, Base anchoring, unlogged-tx alert, for one EVM chain and one agent framework. That's enough for the demo, and the demo is enough to raise on.

## Vibecoding

- [Vibecoding guide](04-vibecoding/VIBECODING.md): session protocol, guardrails, review checklist, prompt library, Arkiv AI tools.
- [Spikes & live decisions](04-vibecoding/SPIKES.md)
- [Progress log](04-vibecoding/PROGRESS.md)
- Root [`CLAUDE.md`](../CLAUDE.md): the instructions every coding agent session loads.

## Sources checked (2026-11-01)

- Arkiv hub (`hub.arkiv.network`), AI tools page, docs (`docs.arkiv.network`: first entity, limits, expiration, query language, Rabdi network).
- `Arkiv-Network/arkiv-sdk-js` (develop, `1.0.0-dev.1`): README, `executeBatch`, creation flags, `watchEntityEvents`.
- Arkiv AI plugin `arkiv@arkiv` v0.4.1 (installed): write-safety, encryption, security-trust skills and errata.
- Founder's technical spec (`Agent Flight Recorder — Technical Spec.md`, 2026-11-01).

Re-verify Arkiv facts on every SDK upgrade (L3 §2, SPIKES.md). ERC-8004 ABIs and addresses are verified in P3 (S11).
