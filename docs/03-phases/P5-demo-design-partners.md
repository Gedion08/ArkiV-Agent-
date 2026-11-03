# Phase P5 — Demo Hardening & Design Partners (weeks 9–10)

**Goal:** a demo that never fails in front of investors, Base mainnet anchoring, and two design partners recording real agents.

| | |
|---|---|
| Entry | P4 exit met |
| Exit | 1) Demo runs 10/10 times from a clean start in < 6 minutes. 2) Anchors on Base mainnet. 3) Two partners with agents recording in their environment for ≥ 7 days. 4) Pitch deck updated with live screenshots + partner logos/quotes |
| Layers | All (hardening), `apps/demo-agent`, L11 (prod infra, runbooks), framework adapters for partners |

---

## 1. Demo script (the pitch)

| Step | On screen | Under the hood | Fallback if live fails |
|---|---|---|---|
| 0 | Dashboard: "Treasury Rebalancer" agent, verify badge ✔, ERC-8004 ID | Staging/prod stack | Pre-recorded video (always ready) |
| 1 | "Ask the agent to rebalance 30 % USDC into WETH" | `apps/demo-agent` (Claude via the AI SDK + Uniswap MCP server through `fr-proxy`) runs 3 swaps on Base Sepolia | Pre-seeded run from 10 min earlier |
| 2 | Rows stream into the timeline: model_call (model id + context hash), tool_call quote, tool_call swap, tx_sign, tx_broadcast, approval (for the > $10k swap, approved in Telegram live) | SDK + proxy + approvals (if P6 is ready; otherwise pre-approved policy shows `allow`) | |
| 3 | "Now the attack: someone stole the agent's key." Run `cast send` from the agent key to an attacker address | Raw tx, bypassing the recorder | Script `tools/demo/attack.sh` |
| 4 | ≤ 90 s: red **UNLOGGED TRANSACTION** alert in the dashboard + phone notification | Watcher | |
| 5 | Open replay: 40 actions before, and the gap where the attack tx has no intent | Dashboard | |
| 6 | Terminal: `fr verify agent …` → PASS with Base anchor tx | Verifier (public RPCs) | |
| 7 | `fr tamper-demo pack.zip --record 120` then `fr verify pack` → **FAIL at seq 120: header hash mismatch** | Proves tamper evidence | |
| 8 | Close: "This is the evidence your compliance team, auditor and insurer can verify without trusting us." | | |

`apps/demo-agent` tasks:
- Scripted, deterministic prompts. Model temperature 0. A fixed seed wallet funded on Base Sepolia (refill job).
- `pnpm demo:reset` resets local state (new lane or new agent) so every demo starts clean.
- `pnpm demo:run` executes steps 1–2. `pnpm demo:attack` executes step 3.
- Health check before the demo: RPCs, Arkiv, API, watcher lag, writer balance, faucet balance.

## 2. Tickets

| ID | Task | Done when |
|---|---|---|
| P5-01 | `apps/demo-agent` + demo scripts + health check | 10/10 runs |
| P5-02 | Pre-recorded fallback video (OBS) for each demo step | Stored in the pitch folder |
| P5-03 | Deploy `RecorderAnchor` to Base mainnet (Safe admin, KMS anchor key ceremony) | Verified contract. Ceremony log |
| P5-04 | Prod infra (Terraform prod account), runbooks (L11 §5.2), status page | Smoke tests green |
| P5-05 | Framework adapters needed by partners (choose from: Vercel AI SDK middleware, Claude Agent SDK hooks, LangGraph/Python sidecar, ElizaOS plugin) | Partner integrated in ≤ 1 day |
| P5-06 | Onboarding guide: "Record your agent in 30 minutes" (docs site page) + `npx @afr/proxy init` polish | A partner engineer does it unaided |
| P5-07 | Partner feedback loop: weekly call template, issue labels, metrics (time-to-first-record, overhead, alert FP rate) | |
| P5-08 | Security pass: threat-model review vs. L11 §6, dependency audit, secrets review, `SECURITY.md` live | Signed off |
| P5-09 | Arkiv grant application + Golem Ecosystem Fund contact (using the demo video) | Submitted |
| P5-10 | Label testnet evidence clearly in UI/packs (Arch §20) | |

## 3. Design-partner programme

- **Targets:** 1 treasury/DeFi team, 1 trading-agent startup, 1 African fintech payment-agent pilot.
- **Offer:** free for 6 months, white-glove integration, roadmap influence. In return: weekly feedback, a case study, logo use, a reference call for investors.
- **Success metrics per partner:** first record < 30 min, overhead p99 < 5 ms in their environment, ≥ 1 real alert investigated with replay, ≥ 1 evidence export shown to their compliance/auditor.
- **Questions to answer** (feeds PRD open questions): which framework, acceptable anchor cadence, privacy level chosen, would the auditor accept the evidence pack, willingness to pay and at what price point.

## 4. Vibecoding script

1. "Read P5 §1. Build `apps/demo-agent` with deterministic scripted steps, using the Vercel AI SDK + `@afr/sdk` + an Uniswap MCP server behind `fr-proxy`. Add `demo:reset`, `demo:run`, `demo:attack`, `demo:health`."
2. "Harden: run the demo 10 times in a loop, collect failures, fix root causes. Report."
3. "Write the onboarding guide (P5-06) as `docs/guides/record-your-agent.md` and polish `fr-proxy init` UX accordingly."
4. "Implement the framework adapter for <partner framework> (P5-05)."
