# Phase P2 — Evidence Store, Batching & Encryption (weeks 3–4)

**Goal:** sealed records leave the machine as encrypted, signed, read-only, evidence-locked batches on Arkiv (Rabdi testnet), behind the `EvidenceStore` interface, with a Postgres fallback. The API gets its first endpoints (agents, recorder keys, checkpoints).

| | |
|---|---|
| Entry | P1 exit met. Arkiv access key + funded writer account (faucet). ERC-8004 test agent registered on Base Sepolia (or a mock) |
| Exit (demo) | Proxy run → batches appear on the Rabdi explorer. `afr.batch.v1` entities are readonly, owned by the lock address. A script decrypts them with the operator reader key and re-verifies every record hash. Kill Arkiv access mid-run → batches buffer → recover without duplicates |
| Layers | L3 (all except rolling expiry), L4 (§2–§6, §10–§12), L2 (batcher, uploader, outbox), L8 (minimal) |
| Requirements | STO-01…STO-07, PRV-01…PRV-03 (levels 0/1), PRV-07, INT-03 publish |

---

## Week 3 — spikes, store, frame

| ID | Task | Ref | Done when |
|---|---|---|---|
| P2-01 | **Arkiv spikes S1–S10** (scripts + `SPIKES.md` results table) | L3 §12 | Every row has a result + decision |
| P2-02 | Update L3 §5 names / ADR-011 based on S2/S3. Regenerate anything affected | ADR-011 | Docs consistent |
| P2-03 | `@afr/store` types, schemas, privacy allowlists | L3 §3, §5 | Attribute-count/name tests |
| P2-04 | Frame encode/decode/pad | L3 §4 | Round-trip + max-size property |
| P2-05 | MemoryStore with failure injection + conformance suite | L3 §10–11 | C1–C10 green on memory |
| P2-06 | PostgresStore (+ triggers) | L3 §9 | Conformance green on pg |
| P2-07 | `@afr/crypto`: batch encryption, DEK wrap, KEK, HPKE keygrants, reader keys + backup, HMAC commitments, at-rest sealing | L4 | K1–K4, K6, K9, K10 |

## Week 4 — Arkiv, uploader, API v0

| ID | Task | Ref | Done when |
|---|---|---|---|
| P2-08 | ArkivStore + WriterQueue (state machine, predicted keys, lock, readback) | L3 §7 | Conformance green on Rabdi (`ARKIV_E2E=1`) |
| P2-09 | `listBatches` keyset pagination + equivocation detection | L3 §8 | |
| P2-10 | Recorder batcher (close triggers, split, padding, flags at level 1) + uploader wired to the WriterQueue + journal batch states | L2 §4, §9 | R7, R8 |
| P2-11 | Epoch KEK lifecycle in the recorder + keygrant publishing before the first batch of an epoch | L4 §5 | |
| P2-12 | Delegation + agent profile publishing (`afr.delegation.v1`, `afr.agent.v1`) before batches | L2 §9, L3 §5 | Batches never precede their delegation |
| P2-13 | `apps/api` v0: SIWE auth, orgs, agents (+ watch-key provisioning), recorder keys, recorder endpoints (heartbeat, checkpoints, intents, delegations, config) | L8 §3–§4.4 | P2, P5 |
| P2-14 | Recorder outbox → API | L2 §10 | Idempotent |
| P2-15 | Mirror mode (dual-write to Postgres) | L3 §9 | |
| P2-16 | `tools/scripts/decrypt-agent.ts`: fetch batches from Arkiv, decrypt with `.afrkey`, verify hashes (a precursor of the full verifier) | | Exit demo |

## Definition of done

- [x] Conformance suite green on memory, Postgres and Rabdi (P2-05, P2-06, P2-08).
- [x] A cost measurement (S6) recorded with real numbers, and the cost model in Arch §12.2 updated (exit-demo receipts per entity type).
- [x] Chaos: Arkiv 429/timeout/lost response injected → zero duplicate entities, zero lost batches (`packages/recorder/test/chaos.test.ts`, 3 seeds, + revert and a crash).
- [x] No plaintext in any Arkiv attribute (automated check over all created entities in the e2e run: `tools/scripts/exit-demo.ts` canary read-back on Rabdi, and the chaos test over every schema).

## Vibecoding script

1. "Read L3 fully. Do P2-01: write spike scripts under `tools/spikes/` and run them against Rabdi. I'll provide `ARKIV_ACCESS_KEY` and `AFR_ARKIV_WRITER_KEY` in `.env`. Fill `docs/04-vibecoding/SPIKES.md`."
2. "Based on SPIKES.md, do P2-02 (update docs, list every change)."
3. "Do P2-03 to P2-05."
4. "Do P2-06 (testcontainers)."
5. "Read L4 fully. Do P2-07."
6. "Do P2-08 and P2-09 against Rabdi."
7. "Do P2-10 to P2-12 in the recorder."
8. "Read L8 §1–§4.4. Do P2-13 and P2-14."
9. "Do P2-15, P2-16, then run the exit demo and update PROGRESS.md."

## Risks

| Risk | Mitigation |
|---|---|
| Evidence lock not possible in one tx (S3) | Fallback per ADR-011. Document the reduced guarantee in the PRD trust model |
| Rate limits on Rabdi | Bigger batches. Request a higher quota through Arkiv Discord/grant contact |
| SDK 1.0 breaking changes mid-phase | Exact pin. Upgrade only between phases |
| Testnet reset | Postgres mirror + journal archive. Base anchors (P3) |
