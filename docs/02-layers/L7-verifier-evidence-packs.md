# L7 — Verifier (`fr verify`) & Evidence Packs

> Open source (Apache-2.0). It must never depend on AFR servers. **If the verifier passes, the evidence holds. If it fails, it says exactly where and why.**

| | |
|---|---|
| Packages | `packages/verifier` (isomorphic library), `apps/cli` (`fr` binary / `npx @afr/cli`) |
| Depends on | `@afr/core`, `@afr/crypto`, `@afr/store` (read-only; Arkiv + "pack" store), `@afr/identity`, `viem`, `jszip`/`fflate` (packs), `pdf-lib` (pack summary) |
| Requirements | VER-01…VER-07, DSH-06, DSH-08, C21 |
| Phase | P3 (structural + full verify, agent mode), P6 (packs, prove, disclosures, attestations) |

---

## 1. Inputs and trust assumptions

| Input | Trusted? | Source |
|---|---|---|
| Base (anchor chain) RPC | Trusted for chain data (use your own node, or 2 providers in `--paranoid`) | user-supplied or default public |
| Identity chain RPC | same | |
| Arkiv RPC | **Untrusted.** Everything read is checked by signature/Merkle/anchor | |
| Evidence pack | **Untrusted.** Same checks | file |
| Reader key | needed only for full mode | user |
| `ANCHOR_CONTRACTS` registry | trusted (ships with the verifier; overridable) | `@afr/core` |

---

## 2. Verification levels

| Level | Needs | Proves |
|---|---|---|
| **L-S Structural** | public data | Batches are signed by delegated keys. Seq is contiguous. Chain roots link. Merkle roots match the public record hashes. Per-record signatures. Anchored checkpoints are included in Base roots. No equivocation |
| **L-F Full** | + reader key (or disclosure) | All of L-S, plus each decrypted header hashes to its public record hash, `prev_hash` links, per-type schema validity, commitments recomputed from bodies, approvals' EIP-712 signatures, policy hashes |
| **L-A Anchored-only** | Base + a single claim | A given (agent, lane, seq_to, chain_root) was anchored at time T |

---

## 3. Algorithm [NORMATIVE for result semantics]

```
verifyAgent(agentId, opts):
  R = report(agentId)

  # 1 identity
  id = resolveAgent(agentId)                                   → ID_UNRESOLVED (fail) if not found
  afr = id.registration.afr ?? opts.override                   → ID_NO_AFR_SERVICE (warn)
  profile = latest valid afr.agent.v1 signed by operatorAt(now)  → PROFILE_INVALID (warn)

  # 2 delegations
  D = listDelegations(agentKey) ∪ listRevocations(agentKey)
  for d in D: verify EIP-712 sig; signer == operatorAt(d.notBefore) or valid parent (L1 §7.1) → DELEGATION_BAD_SIG / DELEGATION_WRONG_SIGNER (that delegation is ignored, warn)

  # 3 batches per lane
  for lane in lanes(agentKey):
    expectSeq = 0; expectRoot = 0x00…; lastAnchored = none
    for B in listBatches(agentKey, lane, from=0, writers=opts.noWriterFilter ? any : profile.writers):
      pub = decodeFrame(B).pub                                  → FRAME_DECODE (fail)
      check pub ⇔ attrs consistent (agent_key, lane, seq range, roots)  → ATTR_MISMATCH (fail)
      group duplicates by seq_from: differing valid batches → EQUIVOCATION (fail)
      if pub.seq_from != expectSeq → SEQ_GAP{expected, got} (fail)
      if pub.prev_chain_root != expectRoot → CHAIN_BREAK (fail)
      root = batchRoot(pub.records)                             ; != pub.batch_root → MERKLE_MISMATCH (fail)
      for r in pub.records: recover(r.hash, r.sig) == pub.session_keys[r.sk] → RECORD_SIG (fail)
      chain = chainRoot(expectRoot, root, pub.seq_to)            ; != pub.chain_root → CHAIN_ROOT_MISMATCH (fail)
      signer = recover(batchDigest(pub), pub.batch_sig)          ; ∉ pub.session_keys → BATCH_SIG (fail)
      for each sk in pub.session_keys: valid delegation covering (agent, lane, scope&1) at anchor-bounded time → DELEGATION_INVALID (fail)
      keccak(ct) == pub.payload_ct_hash                          → CT_HASH (fail)
      [full] KEK = keygrant(reader) → DEK → decrypt               → NO_KEYGRANT (warn: skip full for epoch) / DECRYPT_FAILED (fail)
      [full] for i: keccak(headers[i]) == pub.records[i].hash   → HEADER_HASH (fail)
             header.seq == pub.records[i].seq, prev_hash links, schema valid → HEADER_INVALID (fail)
             commitments recompute from bodies[i]               → COMMIT_MISMATCH (fail) | TRUNCATED/REDACTED/SHREDDED (info)
             approvals: EIP-712 verify approver / attestor allowlist → APPROVAL_SIG (fail)
      expectSeq = pub.seq_to + 1; expectRoot = chain
      record checkpoint candidates
    # 4 anchors
    for C in checkpoints(agentKey, lane):
      verify C.statement sig by a known anchor key (registry)    → CHECKPOINT_SIG (warn)
      verifyAnchorProof(rootOf[C.epoch] on Base, leaf(C), C.proof) → ANCHOR_PROOF (fail)
      C.chain_root must equal our computed chain root at C.seq_to → ANCHOR_MISMATCH (fail)
    tail = seq beyond last anchored checkpoint → UNANCHORED_TAIL{count, since} (info; warn if older than 3× cadence)
    if opts.at: verify only up to the last checkpoint ≤ opts.at

  # 5 attestations (informational)
  list afr.attestation.v1: verify sigs, attach to report

  return R   # PASS if no fail; PASS_WITH_WARNINGS; FAIL with first failing point + all failures
```

**Equivocation tolerance:** byte-identical duplicates (from rollback re-creates) are fine.

**Delegation time bound:** a record's effective time is the **anchor block time** of the first checkpoint covering it. That's what stops backdating with expired keys. For unanchored tails, `ts` is used and the result is marked "unanchored".

---

## 4. Result format

```json
{
  "verifier": "@afr/verifier@1.0.0",
  "format": "afr/1",
  "agent_id": "eip155:8453:0x…:42",
  "level": "structural",
  "result": "PASS_WITH_WARNINGS",
  "checked_at": "2026-11-01T12:00:00Z",
  "rpc": { "base": "https://…", "arkiv": "https://…" },
  "lanes": [
    { "lane": 0, "records": "12844", "batches": 211, "seq_range": ["0","12843"],
      "last_anchor": { "epoch": 4411, "tx": "0x…", "block_time": "2026-11-01T11:52:10Z", "seq_to": "12790" },
      "unanchored_tail": { "count": 53, "oldest_ts": "2026-11-01T11:52:31Z" } }
  ],
  "findings": [
    { "code": "UNANCHORED_TAIL", "severity": "info", "lane": 0, "detail": "53 records after last anchor" }
  ],
  "attestations": [ { "attestor": "0x…", "verdict": "pass", "seq_to": "9000", "scope": "Q3 sample" } ]
}
```

Exit codes: `0` PASS, `1` PASS_WITH_WARNINGS (with `--strict` → 2), `2` FAIL, `3` usage/infra error (RPC down: **never** reported as FAIL).

---

## 5. CLI (`apps/cli`)

```
fr verify agent <agentId> [--lane N] [--from-seq N] [--to-seq N] [--at <iso|block>]
                          [--reader-key file.afrkey] [--json] [--strict] [--no-writer-filter]
                          [--arkiv-rpc URL] [--base-rpc URL] [--identity-rpc URL] [--paranoid]
fr verify pack <file.zip> [--reader-key …] [--offline] [--json]
fr verify record <agentId> <seq> [--disclosure file.json]          # proves a single record (VER-07)
fr prove <agentId> <seq> --out proof.json                           # header hash + merkle path + checkpoint + anchor
fr pack export <agentId> --from <iso> --to <iso> [--reader-key …] [--decrypt|--sealed] --out q3.zip   (v1)
fr disclose <agentId> --seq 120,121 --fields args,result --out disclosure.json                      (v1)
fr attest <agentId> --seq-to N --verdict pass --findings findings.md --key <wallet>                 (v1)
fr keys reader new|import|show ; fr keys session ; fr keys identity ; fr keys writer
fr agent register|show|update-registration ; fr delegate --agent … --session-key … --ttl 24h
fr tamper-demo <pack.zip> --record 120 --field ts      # flips one byte, used in the pitch demo to show FAIL
```

Human output example:

```
✔ identity      eip155:8453:0x5f…:42  operator 0xA1…  (ERC-8004)
✔ delegations   7 valid · 0 revoked
✔ lane 0        12,844 records · 211 batches · seq 0…12,843 contiguous
✔ signatures    12,844 record sigs · 211 batch sigs
✔ chain         chain root linked across 211 batches
✔ anchors       38 checkpoints · last epoch 4411 (Base, 8 min ago) · proofs valid
ℹ tail          53 records not yet anchored (< 10 min)
RESULT: PASS (structural)   — run with --reader-key for full verification
```

---

## 6. Evidence pack format (v1) [NORMATIVE]

A ZIP file (deflate) named `afr-pack-<agent-short>-<from>-<to>.zip`:

```
manifest.json                  # see below; signed
summary.pdf                    # human summary (non-normative, generated from manifest + records)
identity/
  registration.json            # ERC-8004 registration file as of export
  owner_history.json           # Transfer events used for operator resolution
  profile.json                 # signed AgentProfile(s)
delegations/*.json             # signed Delegation / Revocation statements (+ parents)
batches/<lane>/<seq_from>.frame   # exact frame bytes as stored on Arkiv
batches/<lane>/<seq_from>.ref.json # {store, key, tx, block}
keygrants/<epoch>.json         # only when sealed pack includes grants for the recipient
records/<lane>.jsonl           # decrypted mode only: {seq, header_jcs, body} per line
disclosures/*.json             # optional selective disclosures (L4 §9)
anchors/<epoch>.json           # manifest leaves + tree dump + Base tx/receipt/block header
checkpoints/<lane>.json        # CheckpointStatements + proofs
attestations/*.json
verifier/README.md             # how to verify offline, verifier version, sha256 of this pack's files
```

```json
// manifest.json
{
  "format": "afr-pack/1",
  "agent_id": "…", "lanes": [0],
  "range": { "from_ts": "…", "to_ts": "…", "seq": { "0": ["1200", "5400"] } },
  "mode": "decrypted",                       // decrypted | sealed | disclosure
  "created_at": "…", "created_by": "0xOperator…",
  "files": { "batches/0/1200.frame": "sha256:…", "…": "…" },
  "anchors": [{ "chain_id": 8453, "contract": "0x…", "epoch": 4400, "tx": "0x…" }],
  "verifier_min": "@afr/verifier@1.0.0",
  "signature": { "type": "eip712", "primaryType": "PackManifest", "signer": "0x…", "sig": "0x…" }
}
```

- **Decrypted mode:** includes plaintext records, so the auditor needs no keys. The verifier still checks `keccak(header_jcs)` against the signed frames' public hashes and recomputes commitments.
- **Sealed mode:** ciphertext only, plus keygrants for the recipient's reader key. Safe to send over insecure channels.
- **Offline verification:** everything except the Base anchor existence check works offline. `--offline` reports `ANCHOR_NOT_CHECKED_OFFLINE` (warn). The included block header/receipt allows a light check against a known block hash.
- `PackManifest` EIP-712 type: `{ agentKey, fromSeq, toSeq, mode: string, filesHash: bytes32, createdAt: uint64 }`. Add it to L1 §7 when implementing.

### 6.1 `summary.pdf` contents

1. Cover: agent name, ID, operator, period, verification result + verifier version, QR code to the public verify page.
2. Activity: counts by action type, tx count and value by chain (decrypted mode), approvals vs. unapproved, policy blocks.
3. Integrity: lanes, seq ranges, anchors list (epoch, tx, time), gaps (if any, with signed reasons).
4. Alerts in period (from the API export, marked "operational data, not evidence").
5. Notable actions: top 20 by value with seq, timestamp, model, tool, approval.
6. How to verify: CLI commands.

---

## 7. Browser use (dashboard verify badge)

- `@afr/verifier` runs in a Web Worker with incremental verification: it caches `{lane → last_verified_seq, chain_root}` in IndexedDB and verifies only new batches.
- The badge shows ✔ structural / ✔ full / ⚠ / ✖, with the time of the last anchor and a "verify independently" link that opens the CLI command.

---

## 8. Trust summary API (counterparties)

`@afr/verifier` exports `trustSummary(agentId)`. It's structural only and cached for 5 minutes:

```ts
{ agentId, verified: boolean, lastAnchorAge_s, records: string, gaps: number, equivocations: number,
  flags?: { unapprovedTxBatches: number; violationBatches: number },   // privacy ≥ 1
  attestations: { attestor: Hex; verdict: string; seqTo: string; at: string }[] }
```

The hosted version is `GET https://verify.afr.dev/v1/agents/{agentId}/summary`. It's a convenience that third parties shouldn't need to trust, and the response includes the inputs needed to re-run it.

---

## 9. Tests and acceptance criteria

| # | Test |
|---|---|
| V1 | All negative vectors produce their exact expected codes |
| V2 | E2E: verify the demo agent on testnet (structural + full) → PASS |
| V3 | `fr tamper-demo` on a pack → FAIL with `HEADER_HASH` or `CT_HASH` at the right seq |
| V4 | Spam: inject 100 forged batches (valid format, wrong signer) for the agent → still PASS (they're ignored, info-level `IGNORED_UNSIGNED` count) |
| V5 | Equivocation fixture → FAIL `EQUIVOCATION` |
| V6 | RPC down → exit 3, never 2 |
| V7 | Pack export → verify offline → PASS_WITH_WARNINGS (only `ANCHOR_NOT_CHECKED_OFFLINE`) |
| V8 | Browser worker verifies 10k records in < 10 s on a mid-range laptop |
| V9 | Verifier bundle has no import from `apps/*` or the AFR API client (lint rule) |

## 10. Vibecoding prompts

1. "Create `packages/verifier` implementing `verifyAgent` per L7 §3 as a pure async function over injected readers (`ArkivReader`, `AnchorReader`, `IdentityReader`). Return the report shape in §4. Start with structural mode. Test V1, V4, V5 using MemoryStore fixtures built from test vectors."
2. "Add full mode using `@afr/crypto` (keygrant → KEK → DEK → decrypt) and per-record checks."
3. "Create `apps/cli` with commander implementing `fr verify agent`, `fr prove`, `fr keys reader`, human and `--json` output, exit codes per §4. Bundle with tsdown and add `bun build --compile` targets."
4. "(v1) Implement the evidence pack exporter/importer (§6) with a `PackStore` implementing the read side of `EvidenceStore` over a zip. `fr verify pack` reuses `verifyAgent` with PackStore. Add `fr tamper-demo`."
5. "(v1) Generate `summary.pdf` with pdf-lib from the verification report + decrypted records."
