# L10 — Guardrails & Approvals (`@afr/policy`, `apps/approvals`)

> The upsell. The proxy already sees every action before it runs, so blocking is a small step. A blocked attempt becomes evidence too.

| | |
|---|---|
| Packages | `packages/policy` (pure evaluator, runs in recorder + browser dry-run), `apps/approvals` (approval routing + attestation signing; may be merged into `apps/api` at first) |
| Depends on | `@afr/core`, `zod`, `yaml`, price source adapter (Chainlink feeds via viem / aggregator API), AWS KMS (attestation key) |
| Requirements | GRD-01…GRD-06, CAP-11, DSH-10, DSH-11 |
| Phase | P6 |

---

## 1. Policy document

```yaml
version: 1
name: treasury-default
mode: enforce                 # enforce | warn_only (global default; rules may override)
fail: open                    # open | closed — what happens if evaluation errors
approval:
  timeout_s: 900
  channels: [slack, dashboard]
  require_method_above_usd: 50000     # above this, only eip712 approvals count
defaults:
  usd_price_source: chainlink         # chainlink | coingecko | none
  unknown_price: require_approval     # allow | require_approval | deny
rules:
  - id: cap-per-tx
    when: { action: tx_sign }
    limit: { usd_per_tx: 10000 }
    over: require_approval
  - id: cap-daily
    when: { action: tx_sign }
    limit: { usd_per_day: 50000 }      # rolling 24 h, per agent (lane-merged via API counters)
    over: deny
  - id: allow-contracts
    when: { action: tx_sign }
    allow: { to: ["0x2626…(UniversalRouter)", "0x…(Aave Pool)"] }
    otherwise: deny
  - id: allow-tokens
    when: { action: tx_sign, selector: ["0xa9059cbb", "0x095ea7b3"] }   # transfer, approve
    allow: { token: ["USDC", "WETH"] }
    otherwise: deny
  - id: no-unlimited-approvals
    when: { action: tx_sign, selector: ["0x095ea7b3"] }
    deny_if: { approve_amount: unlimited }
  - id: permits-need-approval
    when: { action: msg_sign, typed_primary: ["Permit", "PermitSingle", "PermitBatch"] }
    over: require_approval
  - id: tool-allowlist
    when: { action: tool_call }
    allow: { tool: ["uniswap.quote", "uniswap.swap", "price.get", "fs.read"] }
    otherwise: deny
  - id: business-hours
    when: { action: tx_sign }
    window: { tz: "Africa/Lagos", days: [mon,tue,wed,thu,fri], hours: "08:00-18:00" }
    outside: require_approval
  - id: rate
    when: { action: tx_sign }
    rate: { max: 20, per_s: 3600 }
    over: deny
  - id: new-counterparty
    when: { action: tx_sign }
    if: { counterparty_first_seen: true }
    then: require_approval
```

- `policy_hash = keccak256(utf8(JCS(parsed document)))`. It's recorded in every `policy` header field.
- Validated by a Zod schema. Unknown keys are rejected.
- Versioned in the API (L8 `policies`). The recorder pulls the active version.

## 2. Evaluation semantics [NORMATIVE for decisions]

```
evaluate(event, state) → { decision, rule_id?, reasons[] }
  facts = derive(event): action, tool, to, selector, token (decoded), amount, usd (price), counterparty_first_seen (state), now, typed_primary
  results = for each rule matching `when`: rule outcome ∈ {allow, warn, require_approval, deny}
  decision = max by severity: deny > require_approval > warn > allow   (no match → allow)
  per-rule mode warn_only: deny/require_approval downgrade to "violated" (recorded, not enforced) → flags has_violation
```

- **Determinism:** evaluation uses only the event, the policy and a `state` snapshot (daily totals, rates, seen counterparties). The snapshot hash is recorded in `meta.policy_state_hash` so the result can be re-checked.
- **Latency budget:** ≤ 1 ms p99 for 50 rules (pure functions, precompiled matchers). Price lookups are async and **cached** (60 s TTL, refreshed in the background). The hot path never waits on the network except for approvals.
- **State:** a local SQLite table in the journal (`policy_state`) plus API counters for cross-lane daily totals (eventually consistent; documented).
- **Decoding:** ERC-20 `transfer/approve/transferFrom`, Permit2, Uniswap Universal Router commands (v1), Aave/Compound common calls (v1.1). Unknown calldata → `token: unknown`, which is handled by `defaults.unknown_price`.

## 3. Enforcement points

| Surface | Before | Deny behaviour |
|---|---|---|
| MCP proxy `tools/call` | before forwarding | Return a `CallToolResult { isError: true, content: [{type:"text", text:"Blocked by AFR policy <rule_id>: <reason>"}] }`, so the agent sees a tool error, not a transport error |
| Wallet hook `signTransaction` | before signing | Throw `AfrPolicyError(rule_id)` from the wrapped `signTransaction` |
| `signTypedData` (permits) | before signing | Throw |
| LLM gateway | optional (model/tool allowlists) | 403 with a provider-shaped error body |

Recorded sequence for a block: `tool_call`/`tx_sign` (with `policy.decision = deny`) → `policy_block {ref_seq}`. For approvals: `tx_sign` (decision `require_approval`) → `approval_request {ref_seq}` → `approval {ref_seq: request_seq, decision}` → `tx_broadcast`. Or, on rejection/expiry, `policy_block`.

## 4. Approvals

### 4.1 Flow

```mermaid
sequenceDiagram
  participant A as Agent
  participant R as Recorder
  participant API as AFR API / approvals
  participant H as Approver (Slack/Telegram/Dashboard)
  A->>R: signTransaction(tx)
  R->>R: evaluate → require_approval (rule cap-per-tx)
  R->>R: capture(approval_request)
  R->>API: POST /recorder/approvals {request_seq, request_hash, rule, summary_enc}
  API->>H: notify (buttons / link)
  H->>API: approve (attested) or EIP-712 signature
  API-->>R: long-poll result {decision, method, sig, attestor}
  R->>R: verify sig; capture(approval)
  R-->>A: proceed (sign + broadcast) or AfrPolicyError
```

### 4.2 Summary privacy

The approver needs to see *what* they approve, but the API mustn't see plaintext. So the recorder builds a short human summary (`"Swap 25,000 USDC → WETH on Uniswap, to 0x…"`) and **HPKE-encrypts it to each approver's reader key**. The dashboard decrypts it locally. Slack/Telegram messages show only a non-sensitive line ("Approval needed: tx ≥ $10k, rule cap-per-tx") plus a dashboard link, **unless** the org opts in to `approval.plaintext_in_chat: true` (shown as a warning in settings).

### 4.3 Approval methods (ADR-023)

- **eip712**: the approver's wallet signs `Approval {agentKey, lane, requestSeq, requestHash, decision, expiresAt}`. The recorder verifies the signer ∈ the policy's approver set (addresses or ERC-1271 Safe).
- **attested**: the approvals service verifies the Slack/Telegram user is an authorised approver (mapping in org settings), then signs `ApprovalAttestation` with its KMS key. The recorder verifies against the published attestor address (in `/recorder/config`).
- The policy can require `eip712` above a USD threshold or for specific rules.

### 4.4 Timeouts and failure

- Timeout → `approval {decision: expired}` → `policy_block`.
- API unreachable: `fail: open` → proceed with `meta.approval_unreachable` and a `violated` decision (so it's flagged). `fail: closed` → block.

## 5. Public API (`@afr/policy`)

```ts
parsePolicy(yaml: string): Policy              // throws PolicyError with path
policyHash(p: Policy): Hex
compile(p: Policy): CompiledPolicy
evaluate(cp: CompiledPolicy, ev: PolicyEvent, st: PolicyState, prices: PriceView): Decision
dryRun(cp, events: PolicyEvent[]): DryRunReport   // used by the dashboard (browser)
decode(tx): DecodedCall                           // ABI decoders registry
```

## 6. Tests and acceptance criteria

| # | Test |
|---|---|
| G1 | Golden decision table: 200 (event, policy, state) → expected decision fixtures |
| G2 | Property: adding a deny rule never turns a deny into an allow (monotonicity) |
| G3 | Latency ≤ 1 ms p99 with 50 rules |
| G4 | Proxy deny returns an MCP tool error, and records `policy_block` |
| G5 | Approval E2E: Slack attested + EIP-712 paths, timeout path |
| G6 | Summary never reaches the API in plaintext (request capture test) |
| G7 | Dry-run in browser == recorder decision for the same events |

## 7. Vibecoding prompts

1. "Create `packages/policy` (pure, isomorphic): Zod schema for the YAML in L10 §1, `parsePolicy`, `policyHash` (JCS), `compile`, `evaluate` with the semantics in §2. Add G1 fixtures and G2 property tests."
2. "Add calldata decoders for ERC-20, Permit/Permit2 typed data, and Uniswap Universal Router. Add a cached price view with a Chainlink adapter (viem readContract on feed addresses)."
3. "Wire `evaluate` into the recorder `decide()` (L2) for proxy and wallet hook, with deny behaviours from §3. Test G4."
4. "Implement approvals: recorder long-poll client, API routes (L8 §4.8), Slack interactive + Telegram inline buttons, attestation signing with KMS, HPKE-encrypted summaries. Test G5, G6."
