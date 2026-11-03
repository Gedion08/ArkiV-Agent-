# Agent Flight Recorder — Product Specification Document (PRD)

| | |
|---|---|
| **Status** | Draft v1.0 |
| **Date** | 2026-11-01 |
| **Owner** | Gideon (founder) |
| **Companion docs** | [Architecture](../01-architecture/ARCHITECTURE.md) · [ADRs](../01-architecture/ADRS.md) · [Layers](../02-layers/) · [Phases](../03-phases/) · [Vibecoding guide](../04-vibecoding/VIBECODING.md) |

> **One line:** A flight recorder for AI agents that move money. Every action the agent takes is logged, signed and checkable by anyone, so you can deploy it with real money.

---

## Table of contents

1. [Summary](#1-summary)
2. [Problem](#2-problem)
3. [Why now](#3-why-now)
4. [Vision, mission and positioning](#4-vision-mission-and-positioning)
5. [Target market and segments](#5-target-market-and-segments)
6. [Personas and jobs to be done](#6-personas-and-jobs-to-be-done)
7. [Product principles](#7-product-principles)
8. [Product scope: capabilities map](#8-product-scope-capabilities-map)
9. [User journeys](#9-user-journeys)
10. [Functional requirements](#10-functional-requirements)
11. [Non-functional requirements](#11-non-functional-requirements)
12. [Privacy model (customer-facing)](#12-privacy-model-customer-facing)
13. [Trust model and stated limits](#13-trust-model-and-stated-limits)
14. [Regulatory and compliance mapping](#14-regulatory-and-compliance-mapping)
15. [Competitive landscape and moat](#15-competitive-landscape-and-moat)
16. [Pricing and packaging](#16-pricing-and-packaging)
17. [Go-to-market](#17-go-to-market)
18. [Success metrics](#18-success-metrics)
19. [Release plan (phases)](#19-release-plan-phases)
20. [Risks and mitigations](#20-risks-and-mitigations)
21. [Dependencies](#21-dependencies)
22. [Open questions](#22-open-questions)
23. [Pitch narrative](#23-pitch-narrative)
24. [Glossary](#24-glossary)

---

## 1. Summary

AI agents now hold wallets and act on treasuries, trades and payments. When something goes wrong, nobody can answer the basic questions: *what did it do, in what order, why, which model made the call, and who approved it?* The only record is logs written by the system under investigation and editable by its operator.

**Agent Flight Recorder (AFR)** fixes this in three parts:

1. **Capture with no rewrite.** An MCP proxy, an SDK and a wallet hook record every model call, tool call, transaction and approval.
2. **Make records into evidence.** Each record is hash-chained and signed by a short-lived session key that the operator's wallet authorizes. Records are encrypted client-side, written to **Arkiv** as read-only, retention-priced entities, and anchored to **Base**. Each agent's **ERC-8004** identity points to its log. A free, open-source verifier (`fr verify`) checks everything without trusting us.
3. **Watch the chain.** A watcher indexes every transaction from the agent's wallets and alerts when one has **no matching record**. That catches leaked keys, bypasses and rogue operators, which no log-based tool can see.

The paid product is the **dashboard**: incident timeline and replay, alerts, auditor access, and exportable **evidence packs**. **Guardrails** (spend caps, allowlists, required approvals) are the upsell, enforced by the same proxy.

---

## 2. Problem

### 2.1 The core problem

Companies want agents that move money:

- rebalancing a treasury,
- executing trades,
- paying suppliers,
- running DeFi strategies,
- settling agent-to-agent payments.

Model quality is not what blocks deployment. Accountability is. After an incident, these questions have no trustworthy answer:

| Question | Why it can't be answered today |
|---|---|
| What did the agent do, in what order? | Logs are mutable, partial and owned by the operator. |
| What did it see? Which model and version made the call? | Prompt and context are rarely kept, and never in a form that can be proven. |
| Did a human approve the action, or did it go around the rules? | Approvals sit in Slack threads, not tied to the action. |
| Was it prompt-injected, or was its key compromised? | Nobody can tell "the agent did it" apart from "someone used the agent's key". |
| Can a third party check any of this? | No. "Trust our logs" is the only answer. |

### 2.2 Who refuses "trust our logs"

- **Compliance teams.** They need audit trails for anything touching customer funds.
- **Insurers and auditors.** They won't cover or sign off on what they can't inspect.
- **Counterparties and other agents.** They need evidence before trusting or paying an agent.
- **Regulators.** Record-keeping rules for automated and high-risk systems are tightening (see [§14](#14-regulatory-and-compliance-mapping)).

### 2.3 Concrete story for the pitch

> A treasury agent with a $2M mandate reads a vendor's "updated payment instructions" in an email it was summarising. That text is a prompt injection. It sends $180k to a new address. The ops team's logs show the tool call, but the CISO can't prove which model version ran, what context it saw, or whether the transfer went through the approval workflow. The insurer asks for evidence that the logs weren't edited afterwards. There is none.
>
> With AFR: replay shows the injected email in the context ten actions earlier, the policy result shows `warn` instead of `block` (a misconfigured rule), and the evidence pack verifies against a root anchored on Base before the incident. The claim proceeds.

---

## 3. Why now

1. **Agents are getting wallets.** Smart accounts, session keys, MPC wallets and agent payment rails (x402-style HTTP payments and similar) make it trivial to give an agent money.
2. **Agents are getting identity.** ERC-8004 gives agents an on-chain identity, reputation and validation registry. The "who is this agent" layer exists. The "what has it done" layer does not.
3. **MCP standardised tool use.** Most agent frameworks speak MCP, so one proxy captures most actions with zero rewrite.
4. **Regulatory tailwind.** The EU AI Act's logging obligations for high-risk systems, DORA's ICT incident requirements for financial entities, and financial audit-trail rules all point the same way. *Check current timelines before quoting them.* Parts of the AI Act's high-risk obligations have been proposed for delay.
5. **Verifiable data layers exist.** Arkiv gives queryable, owner-signed, time-scoped (retention-priced) storage. Base gives cheap settlement-grade anchoring.

---

## 4. Vision, mission and positioning

- **Mission:** Make every AI agent that moves money auditable by people who don't trust it.
- **Vision (3–5 yrs):** The standard evidence format for autonomous agents. AFR logs become the input to agent insurance, credit and reputation, a "credit bureau" for agents built on accumulated, verified behaviour.
- **Positioning statement:** *For teams deploying AI agents that move money, AFR is the flight recorder that turns every agent action into third-party-verifiable evidence and catches anything the agent did off the record. Unlike observability tools (Datadog, LangSmith) or chain monitors, AFR ties the agent's reasoning trail to its on-chain identity and its on-chain activity, in a format auditors and insurers can verify themselves.*

---

## 5. Target market and segments

### 5.1 Beachhead (first 12 months)

| Segment | Pain intensity | Buying trigger | Notes |
|---|---|---|---|
| **Treasury and DeFi strategy agents** (DAOs, crypto funds, protocols) | Very high | Mandate size growing, LP/DAO governance demands | Crypto-native. Accept on-chain anchors readily. |
| **Trading-agent startups** | High | Raising, onboarding external capital, exchange onboarding | Want privacy level 0 (strategy is secret). |
| **Agent platforms / launchpads** wanting a "verified agent" badge | Medium-high | Differentiation, ERC-8004 integration | Channel partner: one integration covers many agents. |
| **Fintechs piloting payment agents** (incl. African fintechs) | High | Regulator and partner-bank scrutiny | Founder has local credibility. Compliance-driven sale. |

### 5.2 Expansion (12–36 months)

- Enterprises running procurement and AP agents (ERP-integrated payments).
- Agent marketplaces needing counterparty evidence before agent-to-agent payment.
- Insurers and auditors as **buyers of access** (seats, evidence verification).
- Custodians and wallet providers embedding AFR as a compliance feature.

### 5.3 Market sizing guidance

Size on **agents deployed with wallets × compliance/monitoring spend per agent**. Do **not** size on agent payment volume, which is still tiny and hurts you in diligence. Build the bottom-up model from:

- number of teams running money-moving agents (design partners, ERC-8004 registry counts, agent-framework usage),
- agents per team,
- AFR price per agent per month (tier mix),
- plus auditor/insurer seats.

Top-down cross-check: blockchain-analytics + compliance-tooling spend (the Chainalysis/TRM category) and AI observability spend. *All figures must be sourced at the time of the pitch. Don't invent them.*

---

## 6. Personas and jobs to be done

| Persona | Role | Jobs to be done | What success looks like |
|---|---|---|---|
| **Ayo, agent engineer** (primary user) | Builds and runs the agent | "Integrate recording in an afternoon without slowing my agent." "When something breaks, show me exactly what happened." | One endpoint change. <5 ms overhead. Replay that answers "why". |
| **Maria, head of risk / compliance** (economic buyer at fintechs) | Owns policy and audit | "Prove to the regulator, bank partner and auditor what the agent did and who approved it." "Alert me when it acts outside policy." | Evidence packs accepted by the auditor. Alerts for unapproved high-value actions. |
| **Dev, CTO / founder** (economic buyer at startups) | Signs off deployment | "Let us raise the agent's mandate safely." "Get insured." | Insurer accepts AFR evidence. Mandate grows. |
| **Sam, external auditor / insurer** | Third-party verifier | "Verify logs without trusting the operator or the vendor." | Runs `fr verify` offline and gets a pass/fail with proofs. |
| **Lena, counterparty / validator** | Another agent or protocol deciding whether to trust | "Has this agent ever moved money without approval? Is its log intact?" | Queries public flags and attestations via the ERC-8004 ID. |
| **Kofi, security on-call** | Incident response | "Tell me the instant the agent's key does something unlogged, and let me kill it." | Critical alert in <2 min. One-click/automatic session-key revoke or smart-account pause. |

---

## 7. Product principles

1. **Evidence over logs.** Every record must be verifiable by someone who trusts neither the operator nor us.
2. **Arkiv for evidence, an EVM chain for finality.** Arkiv holds queryable records. Base holds anchored roots. ERC-8004 holds identity.
3. **Minimal public surface.** Public fields are coarse by default. Payloads are encrypted on the customer's machine. Our servers never see plaintext.
4. **Never block the agent.** Recording is asynchronous. Integrity is protected locally (sign + journal) before data leaves the machine. Only guardrail approvals block, by design.
5. **Storage is swappable.** Arkiv sits behind an `EvidenceStore` interface. Changing platform costs days, not months.
6. **Self-authenticating artifacts.** Every AFR object carries its own signature. Arkiv metadata (`$owner`, `$creator`) is never trusted for provenance.
7. **Honest limits.** We state what we can't catch (off-chain actions outside the proxy, reasoning quality) up front.
8. **Open verifier, paid answers.** The verifier and record format are open source and free. The dashboard, alerts, replay, guardrails and evidence packs are paid.

---

## 8. Product scope: capabilities map

| # | Capability | Description | MVP | v1 | Later |
|---|---|---|:-:|:-:|:-:|
| C1 | MCP proxy capture | Transparent proxy for MCP `tools/call` (stdio + Streamable HTTP) | ✅ | | |
| C2 | TypeScript SDK | `wrapTool`, `wrapModel`, `wrapWalletClient` (viem) | ✅ (wallet + model) | full | |
| C3 | Python SDK | Same surface for Python agents (LangChain, CrewAI, etc.) | | ✅ | |
| C4 | LLM gateway mode | OpenAI/Anthropic-compatible base-URL proxy capturing model calls + context hash | | ✅ | |
| C5 | Hash chain + session-key signing | Per-record keccak chain, EIP-191 signatures, EIP-712 delegations | ✅ | | |
| C6 | Local durable journal | SQLite WAL, crash-safe, replays on restart | ✅ | | |
| C7 | Arkiv evidence store | Read-only, evidence-locked batch entities, retention expiry | ✅ | | |
| C8 | Postgres fallback store | For dev, outages, and self-host without Arkiv | ✅ | | |
| C9 | Client-side encryption | DEK per batch, epoch KEK, HPKE-wrapped to readers | ✅ (operator reader) | auditors | |
| C10 | Privacy levels 0/1/2 | Sealed / flags / open | 0, 1 | 2 | |
| C11 | Base anchoring | `RecorderAnchor` contract, rolled-up Merkle anchors | ✅ (Sepolia→Base) | | |
| C12 | ERC-8004 integration | Registration-file service entry, validation responses | identity link | validation | reputation |
| C13 | `fr verify` CLI | Open-source end-to-end verifier, offline mode | ✅ | | |
| C14 | Chain watcher (EVM) | Unlogged-tx detection, seq gaps, broken chain, anchor lag | ✅ (1 chain) | multi-EVM, 4337 | |
| C15 | Chain watcher (Solana) | Same for Solana programs/accounts | | | ✅ |
| C16 | Alerts delivery | Webhook, email, Slack, Telegram | webhook + email | all | PagerDuty |
| C17 | Kill switch | Revoke session key / pause smart account on critical alert | | ✅ | |
| C18 | Dashboard: agents, timeline, replay, alerts, verify badge | Browser-side decryption | ✅ (minimal) | full | |
| C19 | Rich search over decrypted data | Local index (DuckDB-WASM) | | ✅ | |
| C20 | Auditor access (grants) | Forward + historic key grants, revocation | | ✅ | |
| C21 | Evidence packs | Signed ZIP (PDF summary + machine bundle), offline-verifiable | | ✅ | |
| C22 | Guardrails | Spend caps, allowlists, approvals, blocks as evidence | | ✅ | |
| C23 | Human approvals | Slack/Telegram (attested) + wallet-signed (cryptographic) | | ✅ | |
| C24 | Attestations | Auditor/validator verdict entities referencing checkpoints | | ✅ | |
| C25 | Self-hosting | Helm chart / Docker Compose for the whole stack | | | ✅ |
| C26 | Reputation / credit-bureau layer | Scores derived from verified logs, ERC-8004 reputation feedback | | | ✅ |
| C27 | Public agent pages | "Verified by AFR" page per agent, embeddable badge | | ✅ | |

---

## 9. User journeys

### J1 — Onboard an agent (engineer, ≤ 30 min)

1. Sign in to the dashboard with a wallet (SIWE) and create an org.
2. "Add agent": paste or choose an ERC-8004 agent ID, or **register one** through the dashboard (mints on the identity registry from the operator wallet).
3. Choose privacy level (default 0), retention period (default 1 year), and anchor cadence (plan default).
4. Generate a reader key in the browser. It is backed up encrypted with a passphrase and/or exported for the CLI.
5. Install the recorder:
   - `npx @afr/proxy init` writes `afr.config.yaml` and prints the MCP endpoint to point the agent at, **or**
   - `npm i @afr/sdk` and wrap the wallet client / tools.
6. The recorder generates a session key and prompts the operator to sign the delegation (CLI with wallet, WalletConnect link, or KMS).
7. The first action shows up in the dashboard timeline within seconds. The verify badge turns green after the first anchor.
8. Optional: the dashboard proposes the ERC-8004 registration-file update that adds the AFR service entry.

### J2 — Daily operation

- Agent runs. The proxy records with no visible latency.
- Dashboard: agent list shows status, last anchor, alert count.
- Weekly digest email: actions, value moved (decrypted locally → summary computed client-side), alerts, verification status.

### J3 — Incident: unlogged transaction (security on-call)

1. Watcher sees a tx from the agent wallet with no matching `tx_sign` record after a 60 s grace period → **Critical: unlogged transaction**.
2. Alert to Slack/Telegram/webhook with the tx link, the wallet, and the last 5 recorded actions.
3. Optional kill switch revokes the session key (Arkiv revocation entity + smart-account module call) or pauses the smart account.
4. On-call opens **Replay**: the timeline around the tx shows the gap.
5. Exports an evidence pack for the post-mortem and the insurer.

### J4 — Incident: bad trade (risk lead)

1. "Show me every trade over $10k this agent made without human approval in October."
2. Dashboard decrypts the batches locally, runs the query on the local index, lists 3 actions.
3. Step through the 40 actions before the worst one. Context (prompt, tool results) is shown side by side.
4. Mark the incident, add notes, export an evidence pack.

### J5 — Audit (external auditor)

1. Operator grants the auditor's reader key access for a date range (historic + forward).
2. Auditor receives an evidence pack, or uses the read-only auditor seat.
3. Auditor runs `fr verify --pack q3.zip` offline: chain integrity, signatures, delegations, Merkle proofs, Base anchors → PASS.
4. Auditor posts an **attestation** (verdict + findings hash) referencing the checkpoint. Optionally also an ERC-8004 validation response.

### J6 — Counterparty check (agent or protocol)

1. Resolve the agent's ERC-8004 registration file → find the AFR service entry.
2. Query public flags (privacy ≥ 1): `has_unapproved_tx = true` count, seq continuity, last anchor age, attestations.
3. Decide to transact or not. API/SDK `afr.trustSummary(agentId)` for programmatic use.

### J7 — Guardrail approval (v1)

1. Agent attempts a $25k transfer. Policy `require_approval` above $10k.
2. Proxy holds the call (blocking by design) and sends an approval request to Slack/Telegram/dashboard.
3. Approver approves (attested) or signs EIP-712 with a wallet (cryptographic).
4. `approval` record is written. The call proceeds, or times out → `policy_block`.

---

## 10. Functional requirements

Priority: **P0** = MVP (demo + design partners), **P1** = v1 (paid GA), **P2** = later.
Every requirement has an ID. Layer docs reference these IDs.

### 10.1 Capture (CAP)

| ID | Requirement | Pri |
|---|---|---|
| CAP-01 | MCP proxy forwards `initialize`, `tools/list`, `tools/call`, `resources/*`, `prompts/*` transparently. It records `tools/call` request and response as `tool_call` / `tool_result`. Responses are returned **unchanged** (identical JSON value) to upstream. | P0 |
| CAP-02 | Proxy supports stdio upstreams (spawned) and Streamable HTTP upstreams. It exposes both stdio and Streamable HTTP downstream. | P0 |
| CAP-03 | Proxy can front multiple upstream MCP servers and namespace them (`server.tool`). | P1 |
| CAP-04 | TS SDK `wrapWalletClient(viemClient)` records `tx_sign` (with the signed tx hash) **before** broadcast and `tx_broadcast` after. | P0 |
| CAP-05 | TS SDK `wrapModel()` records `model_call` with provider, model ID, version, context hash, output hash, token counts. | P0 |
| CAP-06 | TS SDK `wrapTool(fn, meta)` for non-MCP tools. | P0 |
| CAP-07 | Python SDK with the same surface (web3.py signer wrapper, LangChain callback handler). | P1 |
| CAP-08 | LLM gateway mode: Anthropic- and OpenAI-compatible HTTP proxy capturing model calls by base-URL change. | P1 |
| CAP-09 | Smart-account support: record ERC-4337 user operations (userOpHash) and ERC-7579/Safe module calls. | P1 |
| CAP-10 | Recorder emits `session_start` / `session_end` records binding the session key, delegation hash, recorder version and config hash. | P0 |
| CAP-11 | Capture failures **never** fail the agent's call (fail-open), **except** when guardrails are configured fail-closed. | P0 |
| CAP-12 | The recorder redacts configured fields (regex/JSONPath) from plaintext payloads before encryption. Redactions are noted in the record. | P1 |

### 10.2 Integrity (INT)

| ID | Requirement | Pri |
|---|---|---|
| INT-01 | Every record carries `prev_hash`. `record_hash = keccak256(JCS(header))`. | P0 |
| INT-02 | Every record is signed by the session key (EIP-191 over `record_hash`). | P0 |
| INT-03 | Session keys are authorised by an EIP-712 `Delegation` signed by the ERC-8004 agent owner (operator wallet), published to Arkiv. | P0 |
| INT-04 | `seq` is strictly monotonic per (agent, lane) with no gaps. Restarts resume from the journal. | P0 |
| INT-05 | Records are durably journaled locally **before** the proxied call returns (for tool results) or before broadcast (for `tx_sign`). | P0 |
| INT-06 | Session keys rotate at least every 24 h (configurable) and on restart. | P0 |
| INT-07 | Revocation of a session key is publishable by the operator and honoured by verifier and watcher. | P1 |
| INT-08 | Salted commitments: `args_hash`, `result_hash`, `context_hash` are salted per record (salt only in the encrypted body). | P0 |

### 10.3 Storage (STO)

| ID | Requirement | Pri |
|---|---|---|
| STO-01 | Records are batched (time ≤ 5 s or size ≤ ~96 KiB) into `afr.batch.v1` Arkiv entities. | P0 |
| STO-02 | Batch, checkpoint, delegation, attestation and anchor entities are created `readonly`. | P0 |
| STO-03 | Evidence lock: batch entities are transferred to a keyless lock address in the same atomic Arkiv transaction, so no one can delete them (subject to the P2 spike, see ADR-011). | P0 |
| STO-04 | Expiry = customer retention period (1–7 years), `permissionlessExtension = true`. | P0 |
| STO-05 | `EvidenceStore` interface with Arkiv, Postgres and in-memory implementations. Conformance test suite shared by all. | P0 |
| STO-06 | Writes are queued per writer account, idempotent by batch ID, reconciled by receipt + readback (never blindly retried). | P0 |
| STO-07 | Local journal keeps a batch until it is confirmed on Arkiv **and** anchored on Base, plus N days (default 30). | P0 |
| STO-08 | Fixed-cadence heartbeat batches and size-bucket padding at privacy level 0. | P1 |
| STO-09 | Retention extension service for rolling-expiry customers. | P1 |

### 10.4 Privacy and access (PRV)

| ID | Requirement | Pri |
|---|---|---|
| PRV-01 | Payloads are encrypted client-side (AES-256-GCM DEK per batch, AAD bound to batch identity). | P0 |
| PRV-02 | DEKs are wrapped by a per-epoch KEK (monthly). The KEK is HPKE-wrapped to each reader's X25519 key via `afr.keygrant.v1` entities. | P0 |
| PRV-03 | Privacy levels 0 (sealed), 1 (flags), 2 (open) configurable per agent. Changing it applies to new batches only. | P0 (0,1) / P1 (2) |
| PRV-04 | Auditor grants: forward (add reader) and historic (re-wrap epoch KEKs) without rewriting batches. | P1 |
| PRV-05 | Revocation stops future access (rotate epoch early). The UI states that past access can't be withdrawn. | P1 |
| PRV-06 | Crypto-shredding: destroying an epoch KEK makes that epoch unreadable for everyone who didn't already hold it. | P1 |
| PRV-07 | Our hosted services never receive plaintext payloads or private reader keys. | P0 |
| PRV-08 | Value bucketing for public fields (never exact amounts). | P1 |

### 10.5 Anchoring and identity (ANC)

| ID | Requirement | Pri |
|---|---|---|
| ANC-01 | `RecorderAnchor` contract on Base (Sepolia first). Non-upgradeable, holds no funds, recorder allowlist only. | P0 |
| ANC-02 | Anchor service rolls up (agent, lane, seq_to, chain_root) leaves into one Merkle root per anchor tx. The manifest is published to Arkiv. | P0 |
| ANC-03 | Cadence: every 10 min or N checkpoints, whichever comes first. Configurable per plan. | P0 |
| ANC-04 | Agent's ERC-8004 registration file includes an AFR service entry (log query, anchor contract, verifier URL). | P0 |
| ANC-05 | Auditors can post ERC-8004 validation responses that reference AFR checkpoints. | P1 |
| ANC-06 | Self-host customers can anchor with their own key (single-agent `anchor()` path). | P2 |

### 10.6 Verification (VER)

| ID | Requirement | Pri |
|---|---|---|
| VER-01 | `fr verify agent <agentId>` performs structural verification from public data only. | P0 |
| VER-02 | With a reader key it performs full verification (decrypt, recompute every record hash and commitment). | P0 |
| VER-03 | Verifier depends only on Arkiv RPC + Base RPC + identity-chain RPC. No AFR servers. | P0 |
| VER-04 | Machine-readable output (JSON) and human output. Non-zero exit on failure. | P0 |
| VER-05 | `fr verify pack <zip>` works fully offline except for an optional anchor RPC check. | P1 |
| VER-06 | Verifier is open source (Apache-2.0), with published spec and test vectors. | P0 |
| VER-07 | Prove a single record: `fr prove <agentId> <seq>` outputs a Merkle path to the Base anchor. | P1 |

### 10.7 Watcher and alerts (WAT)

| ID | Requirement | Pri |
|---|---|---|
| WAT-01 | Index every tx from watched addresses on configured EVM chains, with reorg handling. | P0 |
| WAT-02 | Match txs to `tx_sign`/`tx_broadcast` intents by exact tx hash, then (chain, from, nonce), then weak (to, value, calldata hash, time window). | P0 |
| WAT-03 | Raise **Unlogged transaction** (critical) after the grace period (default 60 s). | P0 |
| WAT-04 | Detect **Sequence gap**, **Broken chain**, **Anchor lag**, **Delegation misuse** (record signed by expired/revoked key). | P0 |
| WAT-05 | Detect **Policy breach** and **Unapproved high-value action** (needs plaintext → customer-side watcher or recorder-emitted flags). | P1 |
| WAT-06 | Hosted watcher matches with HMAC tx commitments and never sees plaintext. | P0 |
| WAT-07 | Alert delivery: webhook (signed), email; Slack, Telegram (P1). Dedup, ack, resolve, mute. | P0/P1 |
| WAT-08 | Kill switch: on critical alert, call a configured revoke/pause hook (ERC-7579 module, Safe guard, or webhook). | P1 |
| WAT-09 | ERC-4337 smart accounts: index `UserOperationEvent` by sender. | P1 |
| WAT-10 | Solana watcher. | P2 |

### 10.8 Dashboard (DSH)

| ID | Requirement | Pri |
|---|---|---|
| DSH-01 | Wallet sign-in (SIWE), orgs, members, roles (owner, admin, engineer, viewer, auditor). | P0 |
| DSH-02 | Agent list: status, last action, last anchor, alert count, retention, privacy level, verify badge. | P0 |
| DSH-03 | Timeline: every action in order with type, model, tool, tx, policy, approval. Filters by type/time/session. | P0 |
| DSH-04 | Replay: step through N actions before/after a pivot with decrypted context side by side. | P0 |
| DSH-05 | Alerts view with linked record (or the gap) and on-chain tx. | P0 |
| DSH-06 | Verify badge: live result of the verifier for the latest checkpoint (runs in the browser). | P0 |
| DSH-07 | Rich local search ("trades > $10k without approval") over decrypted cache. | P1 |
| DSH-08 | Evidence-pack export for a time range. | P1 |
| DSH-09 | Auditor management: invite, grant ranges, revoke, audit log of grants. | P1 |
| DSH-10 | Guardrail policy editor with dry-run against history. | P1 |
| DSH-11 | Approvals inbox. | P1 |
| DSH-12 | Public agent page + embeddable badge. | P1 |

### 10.9 Guardrails (GRD) — v1

| ID | Requirement | Pri |
|---|---|---|
| GRD-01 | Policy-as-code (YAML) with versioning. The policy hash is recorded in every decision. | P1 |
| GRD-02 | Rules: spend caps (per tx/day/counterparty, USD-normalised), allowlists (contracts, tokens, tools, recipients), required approvals above threshold, time windows, rate limits. | P1 |
| GRD-03 | Decisions: `allow`, `warn`, `require_approval`, `deny`. Denies produce `policy_block` records. | P1 |
| GRD-04 | Mode per rule: enforce / warn-only. Global fail-open vs fail-closed. | P1 |
| GRD-05 | Approvals via Slack/Telegram (attested by the approval service key) or EIP-712 wallet signature (cryptographic). Timeouts → block. | P1 |
| GRD-06 | Dry-run: evaluate a draft policy against historic decrypted actions. | P1 |

### 10.10 Platform (PLT)

| ID | Requirement | Pri |
|---|---|---|
| PLT-01 | Public REST API (OpenAPI 3.1) for agents, alerts, checkpoints, grants, webhooks. | P0 (internal) / P1 (public) |
| PLT-02 | Recorder API keys scoped per agent. | P0 |
| PLT-03 | Usage metering (actions, batches, bytes × retention, anchors) → billing (Stripe). | P1 |
| PLT-04 | Audit log of every admin action (who granted what to whom). Itself recorded as AFR records of a "platform agent". | P1 |
| PLT-05 | Multi-tenant isolation. Per-tenant data never visible across tenants. | P0 |

---

## 11. Non-functional requirements

| Area | Requirement |
|---|---|
| **Latency** | Proxy adds ≤ 5 ms p99 (hash + sign + journal) per tool call, ≤ 2 ms p50. Arkiv and Base writes are never on the agent path. |
| **Throughput** | One recorder handles ≥ 200 actions/s sustained. One hosted watcher shard handles ≥ 5,000 watched addresses per chain. |
| **Durability** | Zero record loss after `INT-05` journaling, including on crash/kill -9 (fsync'd WAL). |
| **Freshness** | Record visible on Arkiv ≤ 15 s p95 after action. Anchored ≤ 15 min p95. Unlogged-tx alert ≤ 2 min p95 after tx inclusion. |
| **Availability** | Hosted API/dashboard 99.9 %. Watcher 99.9 %. Recorder runs in the customer's environment and degrades gracefully (journal buffering) when Arkiv/Base/API are down. |
| **Security** | Session keys never leave the recorder host. Anchor keys in KMS/HSM. Reader private keys only in the customer's browser/CLI. SOC 2 Type I by v1 + 6 months. |
| **Privacy** | Hosted services hold only public data, wrapped keys and HMAC commitments. |
| **Verifiability** | Any third party can reproduce verification with open-source code and public RPCs. |
| **Portability** | Swapping the evidence store must not invalidate old proofs. |
| **Compatibility** | Node ≥ 22.10, Bun; Python ≥ 3.10 (v1). MCP spec revisions supported by the official TS SDK. |
| **Observability** | OpenTelemetry traces/metrics from every service and from the recorder (opt-in export). |
| **Cost** | Storage cost per agent per month within plan margin at p90 volume (see cost model in Architecture §12). |
| **Accessibility** | Dashboard meets WCAG 2.2 AA. |

---

## 12. Privacy model (customer-facing)

Arkiv is a **public** database. Anything in an attribute or in the clear is world-readable forever (until expiry), and expiry or deletion does not retract copies someone already took. AFR's rules:

| What | Where | Visible to |
|---|---|---|
| Prompts, context, tool args/results, tx details, approvals | Encrypted batch payload | Holders of a granted reader key only |
| Record hashes, signatures, seq numbers, batch roots | Batch payload "public section" | Everyone |
| Agent ID, seq range, roots, timestamps (block-level) | Arkiv attributes | Everyone |
| Flags: `has_tx`, `has_block`, `has_unapproved_tx` | Arkiv attributes (privacy ≥ 1) | Everyone |
| Action type, value bucket, counterparty | `afr.action.v1` entities (privacy 2) | Everyone |
| Watched wallet addresses | Agent profile (privacy ≥ 1 public; level 0 encrypted, shared with hosted watcher only) | Configurable |
| Tx commitments (HMAC of tx hashes) | Batch public section | Everyone (meaningless without the watch key) |

Guarantees we make:
- We never receive plaintext payloads or reader private keys.
- Encrypted payloads are padded to size buckets at level 0, so batch size doesn't leak activity volume (P1).
- **Limits we state:** batch count and timing are public (mitigated by fixed-cadence heartbeats at level 0). The agent's on-chain transactions are public anyway, by the nature of blockchains.

---

## 13. Trust model and stated limits

**What AFR proves:**
1. A given sequence of records was signed by session keys that the agent's operator authorised.
2. No record in an anchored range was altered, removed, inserted or reordered after anchoring.
3. Records existed no later than the Base block that anchored them.
4. Every on-chain transaction from watched wallets either matches a recorded intent or raised an alert.
5. Blocked attempts and approvals are part of the same evidence.

**What AFR does not prove (say this before investors do):**
- That the model reasoned well. We record *what* happened, not whether it was wise.
- Purely off-chain actions taken **outside** the proxy/SDK (e.g. the agent calls an HTTP API directly). On-chain actions outside the recorder *are* caught by the watcher.
- That the recorder host wasn't compromised **before** signing. A compromised host can sign false records. Short-lived scoped session keys, anchors and the watcher limit the window.
- The window between the last anchor and an incident is protected by signatures + Arkiv write, not yet by Base finality (≤ cadence, default 10 min).

---

## 14. Regulatory and compliance mapping

> ⚠️ Verify every date and article against current official texts before using them in sales or pitch material. Several timelines are in flux.

| Framework | Relevance | AFR features that help |
|---|---|---|
| **EU AI Act** — record-keeping / automatic logging for high-risk systems (Art. 12), deployer log retention (Art. 19/26: at least 6 months unless other law says otherwise), human oversight (Art. 14) | Agents doing credit scoring or other Annex III uses are high-risk. Logging must allow traceability. | Automatic logs, tamper evidence, retention-priced expiry, approval records (human oversight evidence). |
| **DORA** (EU financial entities, applies since Jan 2025) | ICT incident management, logging, third-party ICT risk | Incident timeline, evidence packs, alerting. Note: AFR may itself become an ICT third-party provider to customers. |
| **MiCA / Travel Rule** (crypto-asset service providers) | Record-keeping of transfers | Linked tx records with counterparties (encrypted). |
| **SOC 2 / ISO 27001** (customers' own audits) | Change and access logging | Evidence packs as audit artifacts. |
| **GDPR / NDPA (Nigeria) / Kenya DPA / POPIA** | Personal data in prompts/context | Client-side encryption, redaction, crypto-shredding, data-minimising expiry, region-pinned hosted components. |
| **Financial record retention** (e.g. 5–7 years broker/dealer-style rules, local central-bank rules) | Retention periods | Retention setting 1–7+ years, priced accordingly. |
| **Insurer requirements** (emerging AI/crypto cover) | Evidence for claims and underwriting | Evidence packs, attestations, verification badge. |

Product commitments: publish a **compliance mapping whitepaper** (P1). Offer EU-region hosting for control-plane data (P1). Get legal review of the "personal data on a public chain" question (encrypted payloads + crypto-shredding) before EU enterprise sales.

---

## 15. Competitive landscape and moat

| Category | Examples | What they do | Why it's not enough |
|---|---|---|---|
| APM / logging | Datadog, Grafana, Splunk | Operator-controlled logs | Not third-party-verifiable. No on-chain identity. Can't see txs that never hit logs. |
| LLM observability | LangSmith, Langfuse, Arize, Helicone, AgentOps | Traces of prompts/tools | Same: operator-controlled, no evidence format, no chain linkage. |
| Chain analytics / monitoring | Chainalysis, TRM, Forta, Hypernative | On-chain risk and alerts | No view of agent intent/reasoning. Can't tell a logged action from an unlogged one. |
| Wallet policy engines | Turnkey, Privy, Fireblocks, Safe guards, Lit | Pre-signing policies | Enforcement without an evidence trail of *why*. No reasoning context. |
| Attestation infra | EAS, ERC-8004 validation registry | Generic attestations | Primitives, not a product. AFR uses them. |
| DIY | "Datadog + a hash on-chain" | Cheap | No standard format, no delegation/identity binding, no unlogged-tx detection, no auditor workflow. |

**The moat:**
1. **The watcher.** Cross-checking chain activity against intent records is the feature nobody else can copy from logs. The founder's blockchain-analytics background is what makes it work.
2. **The standard evidence format.** Open spec + open verifier → auditors and insurers learn one format → network effect.
3. **Accumulated verified history** → reputation/credit layer (data network effect).
4. **ERC-8004-native.** First mover on "identity → evidence" linkage.

Arkiv is the substrate, not the moat. It sits behind an interface.

**"Why not Datadog plus a hash on-chain?"** Datadog can't produce evidence a third party accepts (no signed, delegated, chained records), can't link to an agent's on-chain identity, and can't detect transactions that never hit the logs.

---

## 16. Pricing and packaging

> Hypotheses to validate with design partners. Arkiv mainnet pricing is not yet public. Keep retention pricing formula-driven (Architecture §12).

| Plan | Price (hypothesis) | Includes |
|---|---|---|
| **Developer** (free) | $0 | 1 agent, 10k actions/mo, 30-day retention, testnet anchoring, community support, verifier |
| **Team** | $299 / agent / mo (volume discounts) | 250k actions/agent/mo, 1-year retention, Base anchoring every 10 min, alerts (webhook/email/Slack/Telegram), dashboard, replay, 2 auditor seats |
| **Business** | $999 / agent / mo | 2M actions, 3-year retention, guardrails, approvals, evidence packs, kill switch, 5-min anchors, SSO |
| **Enterprise** | Custom | 7+ year retention, self-host, dedicated anchors, custom chains, EU hosting, SLA, compliance support |

Add-ons:
- **Retention fee:** per GB-year beyond the plan (cost-plus over Arkiv storage price + margin).
- **Auditor / insurer seats:** $X/seat/mo, or free for auditors (adoption lever) with paid evidence-pack verification for insurers.
- **Platform partner pricing:** per-agent rev-share for agent platforms offering "Verified by AFR".
- **Later:** reputation/credit-score API, priced per query.

---

## 17. Go-to-market

1. **Design partners (months 0–3):** 3 agent teams (target: 1 treasury/DeFi, 1 trading startup, 1 African fintech payment agent). Free in exchange for weekly feedback and a logo/case study. *Three teams piloting is the strongest slide you can have.*
2. **Developer-led motion:** open-source verifier + spec + SDKs, MCP-registry listing, framework integrations (start with whichever framework the design partners use; see Open Questions), templates (`create-afr-agent`).
3. **Ecosystem:** ERC-8004 community, Base ecosystem, Arkiv/Golem grant and showcase, agent-platform partnerships.
4. **Compliance-led motion (fintech):** compliance mapping whitepaper, auditor partnerships (one Big-4 or crypto-native audit firm accepting AFR evidence packs), insurer partnership.
5. **Content:** "Agent incident" post-mortems, a public "Verified agents" leaderboard.

---

## 18. Success metrics

| Stage | North star | Supporting metrics |
|---|---|---|
| MVP | Demo works end to end live | Proxy overhead p99 < 5 ms. Alert latency < 2 min. `fr verify` passes on 100 % of anchored ranges. |
| Design partners | 3 teams in production pilot | Time-to-first-record < 30 min. Weekly active agents. Partner NPS. |
| v1 GA | Paying agents | MRR, # agents, actions/month, evidence packs exported, auditor verifications run, gross margin per agent |
| Network | Third-party verifications | # external verifiers/auditors, # attestations, # agents with AFR in their ERC-8004 registration |

Guardrail metrics (must not regress): records lost (target 0), false-positive unlogged-tx alerts (< 1 per agent per month), agent-path errors caused by AFR (0).

---

## 19. Release plan (phases)

Detail lives in [`docs/03-phases/`](../03-phases/).

| Phase | Name | Weeks (1 eng) | Outcome |
|---|---|---|---|
| P0 | Foundations | 0.5 | Monorepo, CI, conventions, test vectors harness |
| P1 | Recorder core | 1–2 | Record format, JCS, hash chain, signing, journal; proxy forwards one MCP server |
| P2 | Evidence store | 3–4 | `EvidenceStore` + Arkiv + Postgres; batching; encryption; evidence lock spike |
| P3 | Anchor + verify | 5–6 | `RecorderAnchor` on Base Sepolia; anchor service; `fr verify` end to end |
| P4 | Watcher + dashboard | 7–8 | EVM watcher + 3 alerts; minimal dashboard (timeline, replay, alerts, badge) |
| P5 | Demo + design partners | 9–10 | Hardened demo script; 2 partners integrated; Base mainnet anchors |
| P6 | v1 GA | 11–22 | Guardrails, approvals, auditor grants, evidence packs, privacy L2, Python SDK, LLM gateway, kill switch, billing |
| P7 | Scale & enterprise | 23–40 | Solana, multi-EVM, 4337, self-host, SSO, EU region, SOC 2 |
| P8 | Network layer | 40+ | Reputation/credit bureau, ERC-8004 validation market, insurer API |

---

## 20. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Teams just use Datadog + on-chain hash | High | High | Lead with the watcher + standard evidence format accepted by a named auditor/insurer. |
| Small market today | High | Medium | Sell to platforms (one integration → many agents). Fintech compliance segment. Expand to enterprise AP agents. |
| Arkiv pre-production / changes (it already retired testnets once) | High | Medium | `EvidenceStore` interface, Postgres fallback, Base anchors as source of truth, version-pinned SDK, spike each release. |
| Arkiv pricing makes long retention expensive | Medium | Medium | Batching, compression, tiered retention (full payload for N years, checkpoints-only after), formula-based pricing. |
| Public metadata leaks strategy | Medium | High | Privacy level 0 default, padding, heartbeats, coarse buckets. |
| Recorder host compromise | Medium | High | Short-lived scoped session keys, revocation, watcher, KMS option, attested recorder builds (later: TEE). |
| ERC-8004 spec churn | Medium | Low | Isolate in identity adapter. Support registration-file versions. |
| Regulatory claims overreach | Medium | High | Legal review. "Helps meet" language, never "makes you compliant". |
| Adds latency / breaks agents | Low | High | Fail-open by default, unchanged forwarding, conformance tests against popular MCP servers. |
| Key management UX friction (delegation signing) | Medium | Medium | WalletConnect deep link, KMS signer, 7-day delegations, dashboard one-click. |
| Personal data on public chain (GDPR) | Medium | High | Encrypt everything, redaction, crypto-shredding, legal opinion. |

---

## 21. Dependencies

| Dependency | Version / status (2026-11-01) | Notes |
|---|---|---|
| Arkiv network | **Rabdi** public testnet, chain ID `7794095`, RPC `https://rpc.rabdi.db-chain.testnet.arkiv.network`, 2 s blocks, gas in tGLM. Mainnet timeline not published. | Access key from hub; heavily rate-limited public RPC. |
| `@arkiv-network/sdk` | `1.0.0-dev.x` on `develop` (README shows `^0.9.0`; plugin skills verified on 0.8.1/Tiramisu) | Pin exact versions. Re-verify APIs each upgrade. |
| Base / Base Sepolia | 8453 / 84532 | Anchor contract. |
| ERC-8004 registries | Identity, Reputation, Validation | Confirm deployed addresses and current registration-file schema at implementation time. |
| MCP | Official TS SDK `@modelcontextprotocol/sdk` | Track spec revisions. |
| Golem/Arkiv grant | TBD | See open questions. |

---

## 22. Open questions

- [ ] Arkiv mainnet pricing, write limits and per-tx size limits once the post-Devcon release is public.
- [ ] Does the current Arkiv chain allow `changeOwnership` to a keyless address inside the same `executeBatch` as the create (evidence lock)? → P2 spike.
- [ ] Attribute-name charset on the node (underscores?) → P2 spike. Fall back to dotted names.
- [ ] Which agent framework the first design partners use (sets SDK priority: LangGraph? Vercel AI SDK? ElizaOS? CrewAI? Claude Agent SDK?).
- [ ] Anchor cadence that design partners and auditors accept.
- [ ] Grant fit: Golem Ecosystem Fund scope and timeline.
- [ ] Will a named auditor/insurer accept AFR evidence packs? (GTM-critical)
- [ ] Hosted watcher: do customers accept sharing the watch key (HMAC) for hosted matching, or require self-host?
- [ ] Legal: is client-side encrypted personal data on a public store acceptable under GDPR with crypto-shredding?
- [ ] Price-oracle source for USD normalisation in guardrails (Chainlink feeds vs. aggregator API).

---

## 23. Pitch narrative

1. **One line:** "A flight recorder for AI agents that move money."
2. **Problem:** Agents now hold wallets. Nobody can audit them. Companies won't deploy what they can't audit. Tell the prompt-injection story ([§2.3](#23-concrete-story-for-the-pitch)).
3. **Demo (the part that wins the room):**
   1. A trading agent runs a few swaps. Each action appears in the dashboard with model, reasoning hash and approval.
   2. Simulate an attack: send a tx from the agent's key **outside** the recorder.
   3. Watcher fires: "unlogged transaction from agent wallet".
   4. Replay the timeline, then run `fr verify` against the Base-anchored root to prove the log wasn't altered. Tamper with one byte locally and show it fail.
4. **Why now:** ERC-8004 identity, agents with wallets, MCP everywhere, regulatory tailwind.
5. **Why this design:** MCP proxy (zero rewrite), Arkiv (queryable, signed, retention-priced evidence), Base anchoring (settlement-grade proof), chain watcher (the part nobody else has).
6. **Why you:** Regulatory-grade analytics across multiple chains. This is compliance tooling for a new kind of account holder.
7. **Market:** Sized on agents with wallets × compliance spend.
8. **Business model and traction:** Pricing ([§16](#16-pricing-and-packaging)) + design partners.
9. **Risks and mitigations,** stated before anyone asks ([§20](#20-risks-and-mitigations)).
10. **Ask:** Pre-seed amount, Golem/Arkiv grant, pilot partners.

---

## 24. Glossary

| Term | Meaning |
|---|---|
| **Action record** | One canonical, signed AFR record (header + encrypted body). |
| **Header** | The hashed part of a record: metadata + commitments. Encrypted at rest, but its hash is public. |
| **Body** | Plaintext args/results/context + salt. Encrypted. Bound to the header by commitments. |
| **Lane** | An independent hash chain for one agent (one per recorder instance). MVP: lane 0 only. |
| **Session key** | Short-lived secp256k1 key in the recorder that signs records. |
| **Delegation** | EIP-712 statement by the operator wallet authorising a session key for an agent/lane/time window. |
| **Batch** | Group of consecutive records stored as one Arkiv entity. Has a Merkle `batch_root`. |
| **Chain root** | Rolling hash over batch roots for an (agent, lane). Commits to the full history. |
| **Checkpoint** | Public statement of (agent, lane, seq_to, chain_root), included in an anchor. |
| **Anchor** | Base transaction committing a Merkle root over many checkpoints. |
| **Evidence lock** | Transferring a read-only entity to a keyless address so nobody can delete it before expiry. |
| **DEK / KEK** | Data-encryption key (per batch) / key-encryption key (per agent epoch). |
| **Keygrant** | Arkiv entity carrying an epoch KEK HPKE-wrapped to one reader. |
| **Tx commitment** | HMAC of a tx hash under the tenant watch key, published so the hosted watcher can match without plaintext. |
| **Evidence pack** | Signed export bundle for auditors/insurers, verifiable offline. |
| **Unlogged transaction** | On-chain tx from a watched address with no matching recorded intent. |
| **Privacy level** | 0 sealed / 1 flags / 2 open. Controls which fields are public. |
