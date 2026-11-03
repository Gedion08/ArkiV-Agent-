# Phase P6 — v1 General Availability (weeks 11–22)

**Goal:** a sellable product: guardrails and approvals (the main revenue driver), auditor access, evidence packs, privacy level 2, Python SDK, LLM gateway, smart-account support, kill switch, billing, public agent pages. External crypto review and contract audit done.

| | |
|---|---|
| Entry | P5 exit met. ≥ 2 partners live |
| Exit | First paying customer on the Team/Business plan. Crypto review + contract audit findings fixed. SOC 2 Type I readiness started. Format v1 final (no "-rc") |
| Requirements | All P1-priority requirements in PRD §10 |

---

## Milestones (2-week sprints)

### Sprint 6.1 (wk 11–12): Guardrails core
| ID | Task | Ref |
|---|---|---|
| P6-01 | `@afr/policy` parser, hash, compile, evaluate + decoders + price view | L10 §1–§2, §5 |
| P6-02 | Recorder `decide()` + enforcement in proxy, wallet hook, signTypedData | L10 §3 |
| P6-03 | Policy API + recorder config sync | L8 §4.8 |
| P6-04 | Dashboard policy editor + browser dry-run | L9 §4.9 |

### Sprint 6.2 (wk 13–14): Approvals + kill switch
| ID | Task | Ref |
|---|---|---|
| P6-05 | Approvals service: requests, HPKE summaries, Slack + Telegram + dashboard inbox, EIP-712 + attested | L10 §4, L9 §4.10 |
| P6-06 | Kill switch: pre-signed revocations, webhook action, `AfrKillSwitchModule` (beta, audited later) | L6 §6.3, L5 §5 |
| P6-07 | Slack/Telegram notifier adapters + interactive ack | L8 §5.1 |

### Sprint 6.3 (wk 15–16): Auditor access + evidence
| ID | Task | Ref |
|---|---|---|
| P6-08 | Reader management, forward/historic grants, revocation (early rotation), shredding | L4 §7–§8, L9 §4.8 |
| P6-09 | Evidence packs (export, `fr verify pack`, summary.pdf, `fr tamper-demo`) | L7 §6 |
| P6-10 | Selective disclosure + `fr disclose` / `fr verify record` | L4 §9, L7 §5 |
| P6-11 | Attestations (`fr attest`) + ERC-8004 validation response | L5 §4.1, L7 |

### Sprint 6.4 (wk 17–18): Capture breadth
| ID | Task | Ref |
|---|---|---|
| P6-12 | Python SDK + sidecar (web3.py, anthropic/openai wrappers, LangChain handler) | L2 §12 |
| P6-13 | LLM gateway (Anthropic + OpenAI compatible) | L2 §13 |
| P6-14 | Smart accounts: 4337 user ops (SDK + watcher), Safe | L2 §6.1, L6 §3.2 |
| P6-15 | Multi-upstream proxy + namespacing; MCP sampling capture; upstream OAuth | L2 §5 |
| P6-16 | Redaction presets | L2 §8 |

### Sprint 6.5 (wk 19–20): Watcher breadth + privacy L2
| ID | Task | Ref |
|---|---|---|
| P6-17 | Multi-EVM chains (Ethereum, Arbitrum, Optimism, Polygon) + UNEXPLAINED_OUTFLOW + approvals monitoring | L6 §3.2, §4.2 |
| P6-18 | Self-hosted watcher mode (plaintext weak match, policy alerts) | L6 §7 |
| P6-19 | Privacy level 2 (`afr.action.v1`), `watch_mode: public`, public agent page + badge | L3 §5, L4 §10, L9 §4.11 |
| P6-20 | Heartbeats + padding defaults on at level 0 | L2 §9 |

### Sprint 6.6 (wk 21–22): Business + hardening
| ID | Task | Ref |
|---|---|---|
| P6-21 | Metering + Stripe billing + plan limits (never blocks recording) | L8 §6 |
| P6-22 | Search (DuckDB-WASM) + preset queries | L9 §4.6 |
| P6-23 | Rolling expiry + extension job. Tiered retention decision (ADR-014) | L3 §6, L5 §3.5 |
| P6-24 | External crypto review (L1/L4) + Solidity audit (RecorderAnchor, KillSwitch). Fix findings | L11 §6 |
| P6-25 | Pentest API/dashboard. Fix findings | L11 §6 |
| P6-26 | Public API docs + compliance mapping whitepaper | PRD §14 |
| P6-27 | Format v1 final: freeze L1/L4/L7, publish the spec site + vectors | ADR policy |

## Exit checklist

- [ ] All GRD, PRV, VER, WAT P1 requirements implemented with tests.
- [ ] Audit and review reports published (or summaries).
- [ ] Pricing validated with ≥ 3 conversations. First invoice paid.
- [ ] On-call rotation + status page + runbooks rehearsed (game day).

## Vibecoding approach for long phases

- One sprint per working branch. Every task gets its own PR referencing its doc section.
- Start each session with: "Read CLAUDE.md, PROGRESS.md, and the doc sections for task P6-xx. Summarise what you'll change before coding."
- End each session with: "Update PROGRESS.md (done, decisions, open issues) and list any doc changes needed."
