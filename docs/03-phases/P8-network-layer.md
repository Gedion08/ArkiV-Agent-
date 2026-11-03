# Phase P8 — Network Layer: Reputation, Credit & Insurance (week 40+)

**Goal:** turn accumulated, verified agent histories into the network effect: reputation scores, a "credit bureau for agents", insurer underwriting APIs and a validation marketplace built on ERC-8004.

| | |
|---|---|
| Entry | Hundreds of agents with months of verified history. ≥ 1 insurer/auditor partner |
| Exit | Reputation API in production with paying consumers (insurers, protocols, marketplaces) |

---

## Products

### 8A — Agent reputation score
- Inputs (only **verifiable** signals): log integrity (gaps, equivocations: none), anchor freshness, approval coverage of high-value actions (privacy ≥ 1 flags), policy blocks vs. violations, unlogged-tx alerts (resolved/unresolved), attestations (by whom, verdicts), tenure, volume buckets (privacy 2).
- Output: `score (0–1000)`, `components{…}`, `evidence_refs[]` (checkpoint keys, attestation keys). Every component is reproducible by a third party running the open scoring function over public data. The scoring code is open source. Only the aggregation service and the data freshness are paid.
- Published as ERC-8004 **Reputation** feedback by AFR (as a feedback giver) with `feedbackURI` → score report and `feedbackHash`.

### 8B — Underwriting API for insurers
- `GET /v1/underwriting/agents/{id}`: score, incident history (alerts by severity, time to resolve), guardrail configuration hash (policy versions over time, provable via records), approval method mix.
- With operator consent: sealed evidence pack delivery to the insurer's reader key.
- Claims workflow: incident evidence pack → insurer verifies → attestation.

### 8C — Validation marketplace
- Validators (audit firms, independent reviewers, automated re-execution services) register. Operators request validation of a checkpoint range through the ERC-8004 Validation Registry. Validators post `afr.attestation.v1` + `validationResponse`. Fees in USDC via x402 or invoicing.
- Automated validators: re-run the verifier, plus check policy compliance with a disclosed policy, plus statistical anomaly checks.

### 8D — Counterparty gating
- SDK for agent-to-agent commerce: `requireTrust({ minScore, maxAnchorAge, noUnresolvedCritical })` before paying or accepting a task. Works over the public `trustSummary` (L7 §8). x402 middleware: a server refuses payment requests from agents that fail the trust policy.

## Research questions (spike before building)

- Gaming resistance: Sybil agents with clean but empty histories → weight by value-at-risk buckets and attestation quality.
- Privacy vs. reputation: how much does privacy level 0 limit scoring? Offer a zero-knowledge proof path later (prove "no unapproved tx > $X" without revealing records) using ZK over the record commitments. Research only.
- Liability: is a published score a regulated activity (credit-reference rules) in target markets? Legal review.

## Vibecoding note

Start with the open scoring function (`packages/reputation`) as a pure function over verifier reports, with fixtures. Only then build services around it.
