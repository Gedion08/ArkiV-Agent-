# Phase P4 — Chain Watcher & Minimal Dashboard (weeks 7–8)

**Goal:** the moat works. A tx from the agent's wallet that didn't go through the recorder raises a critical alert within ~90 s. A minimal dashboard shows the timeline, replay, alerts and a live verify badge, decrypting in the browser.

| | |
|---|---|
| Entry | P3 exit met |
| Exit (demo) | Demo agent swaps on Base Sepolia through the SDK → rows appear in the dashboard timeline with model, tool, tx, approval columns. `cast send` from the agent key → red `UNLOGGED_TX` row + email/webhook within 90 s. Replay shows the 40 actions before. Verify badge ✔ |
| Layers | L6 (EVM single chain, matcher, log auditor, alert engine), L8 (alerts, channels, notifier email + webhook), L9 (key onboarding, list, overview, timeline, replay, alerts, badge) |
| Requirements | WAT-01…WAT-04, WAT-06, WAT-07 (webhook+email), DSH-01…DSH-06 |

---

## Week 7 — watcher + alerts

| ID | Task | Ref | Done when |
|---|---|---|---|
| P4-01 | Head follower with reorg handling + cursors (Base Sepolia, Anvil) | L6 §3.1 | W3, W8 ✓ (anvil) |
| P4-02 | Watched set + tx filter + observed_txs | L6 §2, §3.2 (EOA only) | |
| P4-03 | Intent intake (API → `tx_intents`) + Arkiv batch reconciliation in the log auditor | L6 §4.1 | |
| P4-04 | Matcher (exact + nonce) with grace timers | L6 §4.2 | W1, W2, W4 |
| P4-05 | Log auditor: SEQ_GAP, BROKEN_CHAIN, EQUIVOCATION, DELEGATION_MISUSE, RECORDER_SILENT, ANCHOR_LAG | L6 §5 | W5 |
| P4-06 | Alert engine + API alert routes + notifier (email via mailpit/Resend, signed webhooks) | L6 §6, L8 §4.5–4.10, §5 | W10, P4 |
| P4-07 | Canary job in staging (hourly unlogged tx) | L6 W9, L11 §5 | One alert/hour, auto-acked |

## Week 8 — dashboard

| ID | Task | Ref | Done when |
|---|---|---|---|
| P4-08 | Scaffold dashboard, SIWE login, org switcher, agent list/overview (API data) | L9 §1, §4.1–4.2 | |
| P4-09 | Reader key onboarding + backup + import | L9 §2 | D7 |
| P4-10 | Decrypt worker + IndexedDB cache + frame fetch (Arkiv, mirror fallback) | L9 §3 | K5 |
| P4-11 | Timeline with grouping, gaps, interleaved alerts | L9 §4.3 | D2 |
| P4-12 | Replay view | L9 §4.4 | |
| P4-13 | Alerts inbox + detail + ack/resolve | L9 §4.5 | |
| P4-14 | Verify worker + badge | L9 §4.2, L7 §7 | D3 |
| P4-15 | Playwright E2E D1–D4, D7 | L9 §8 | Green in CI |

## Definition of done

- [ ] Full demo script (P5 §1) runs end to end on staging without manual fixes.
- [ ] Alert latency measured: p95 < 90 s over 50 runs.
- [ ] No decrypted canary in any network request (D4).

## Vibecoding script

1. "Read L6 §1–§4. Do P4-01 and P4-02 with Anvil tests."
2. "Do P4-03 and P4-04."
3. "Read L6 §5–§6, L8 §4.5–§5. Do P4-05 and P4-06."
4. "Do P4-07."
5. "Read L9 fully. Do P4-08 and P4-09."
6. "Do P4-10 and P4-11."
7. "Do P4-12 to P4-14."
8. "Do P4-15, then run the demo on staging and record alert latency stats in PROGRESS.md."

## Risks

| Risk | Mitigation |
|---|---|
| False positives from recorder outbox delays | Batch reconciliation + auto-resolve `late_intent`. Tune the grace |
| RPC rate limits on block fetch | Paid provider for staging/prod. Backoff. Fallback provider |
| Dashboard scope creep | Only the views in this phase. Everything else is P6 |
