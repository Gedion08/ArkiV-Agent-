# L3 — Evidence Store & Arkiv (`@afr/store`)

| | |
|---|---|
| Package | `packages/store` → `@afr/store` |
| Depends on | `@afr/core`, `@arkiv-network/sdk` (**exact pin**, 1.0.1), `viem`, `cbor-x`, `fflate`, `pg` / `drizzle-orm` (Postgres impl) |
| Used by | recorder (write), anchor service (write), watcher (read), verifier (read), dashboard (read, browser build excludes Postgres) |
| Requirements | STO-01…STO-09, PRV-03, VER-03 |
| Phase | P2 (core), P3 (anchor/checkpoint schemas), P6 (rolling expiry, extension service, tiered retention) |

---

## 1. Responsibilities

- The `EvidenceStore` abstraction plus three implementations: **Arkiv**, **Postgres**, **Memory**.
- Arkiv schemas (attribute sets) for every AFR entity kind.
- The **batch frame** binary format (CBOR + padding).
- The **writer queue**: nonce-ordered, durable, reconciled writes following Arkiv write-safety rules.
- Evidence lock (ADR-011), readonly flags, expiry.
- Typed read paths: batches by (agent, lane, seq), delegations, keygrants, checkpoints, anchors, attestations.
- A conformance test suite that every implementation must pass.

---

## 2. Arkiv facts this layer relies on (verify on every SDK upgrade)

| Fact | Value (2026-11-01) | Source |
|---|---|---|
| Testnet | Rabdi, chain `7794095`, RPC `https://rpc.rabdi.db-chain.testnet.arkiv.network`, WS same host `wss://` | docs.arkiv.network/networks/rabdi |
| Block time | 2 s | docs |
| SDK | `@arkiv-network/sdk` **1.0.1** (exact pin) + `viem` 2.57.7 peer | S1 (2026-11-04) |
| Chains export | `rabdi({ accessKey })`, `localhost` | `src/chains` |
| Writes | `createEntity(schema, values, { expiration })`, `patchEntity`, `extendEntity`, `deleteEntity`, `changeOwnership`, `executeBatch({creates, patches, deletes, extensions, ownershipChanges})` (atomic; applied creates→patches→deletes→extensions→ownership) | SDK source |
| Key prediction | `predictEntityKeys({ owner, count | salts })` (**public** action; keyed by the registry's per-owner `entityNonce`, not the tx nonce; pass the returned `salt` to the create) | S1, S3 |
| Flags | `readonly`, `permissionlessExtension` (immutable at creation) | `src/entity/flags.ts` |
| Limits | 32 attrs (31 with schema), name ≤ 32 B, `str` ≤ 128 B, `bytes` ≤ 128 KiB **total per create/patch** (SDK-checked), page ≤ 100 rows. **Binding in practice:** the RPC rejects calldata above ≈ 131 KB, so a Batch frame + attrs fits up to ≈ 124 KiB of frame | docs reference/limits, S5 |
| Gas | Linear in bytes × lifetime: 96 KiB create ≈ 4.03M gas (1 h) … 4.09M (1 d) … 15.4M (182.5 d); ≈ 650 gas per KiB-day; extension ≈ 46k + 650/KiB-day. Per-tx cap 2²⁴ (EIP-7825); block gas limit 30M; gasPrice 1 gwei on Rabdi | S6 |
| Types | `bool, i32, u64, u256, dec, str, addr, key, bytes`. `bytes` can't be indexed or sorted | SDK README |
| Query | `select().from(schema).where(expr).ownedBy()/createdBy().orderBy(asc|desc one key).limit().offset().fetch()`. `$createdAt`/`$updatedAt` not sortable | SDK README, plugin |
| Events | `watchEntityEvents` follows head only (viem `watchEvent`; `eth_newFilter` is unavailable, so it polls `eth_getLogs`). Events carry key/owner/expiry, no schema or attrs. `eth_getLogs` only covers ≈ the last 1,000 blocks | SDK source, S10 |
| Node quirks | Names are case-sensitive, grammar `^[A-Za-z][A-Za-z0-9._-]*$`, query keywords/type tags reserved (we use lowercase snake_case anyway). State reads at head only (`-32603` otherwise). `eth_estimateGas` drops revert data: decode engine errors (`NotOwner`, `ReadOnlyEntity`, `ExpiryNotExtended`, …) with `eth_call`. Occasional transient HTTP failures on reads (retry reads, never writes). No 429 seen at ≈ 2,450 queries/min | S2, S9, S8 |
| Expiry | `ExpirationTime.fromDays/fromHours/atDate/max()`. **Max lifetime 7,884,000 blocks ≈ 182.5 d from the block of the create or extension**; longer is refused client-side (`InvalidExpiryError`). Extending counts from now and must move expiry later (`ExpiryNotExtended`). No expiry event | SDK `MAX_LIFETIME`, S6, S9 |

> Re-run the **spike checklist** (§12, scripts in `tools/spikes/`) on every SDK upgrade. Results for 1.0.1 on Rabdi: `docs/04-vibecoding/SPIKES.md` S1–S10.

---

## 3. `EvidenceStore` interface

```ts
export type StoreKind = "arkiv" | "postgres" | "memory";

export interface PutRequest<S extends AfrSchemaName = AfrSchemaName> {
  schema: S;
  attrs: AttrsOf<S>;                    // typed per schema (§5)
  payload: Uint8Array;                  // the frame / statement bytes (≤ 120 KiB)
  expiresAt: { days: number } | { date: Date };
  readonly: true;                       // AFR evidence is always readonly (agent profile is the exception)
  permissionlessExtension: boolean;
  lock: boolean;                        // evidence lock (ADR-011)
  idempotencyKey: Hex;                  // e.g. batch_id; used for reconciliation
}

export interface EntityRef { store: StoreKind; key: Hex; txHash?: Hex; block?: bigint }

export interface StoredEntity<S extends AfrSchemaName = AfrSchemaName> {
  ref: EntityRef;
  schema: S;
  attrs: AttrsOf<S>;
  payload: Uint8Array;
  meta: { owner: Hex; creator: Hex; createdAtBlock: bigint; expiresAtBlock: bigint; readonly: boolean; permissionlessExtension: boolean };
}

export interface StoreQuery<S extends AfrSchemaName = AfrSchemaName> {
  schema: S;
  where: Partial<Record<keyof AttrsOf<S>, Cond>>;   // eq / gte / lte / between only (portable subset)
  createdBy?: Hex[];                                // discovery filter (writers declared in agent profile)
  orderBy?: { attr: keyof AttrsOf<S>; dir: "asc" | "desc" };
  pageSize?: number;                                // ≤ 100
  atBlock?: bigint;                                 // pin for consistent pagination
  includePayload?: boolean;                         // default true
}

export interface EvidenceStore {
  readonly kind: StoreKind;
  put(req: PutRequest): Promise<PendingWrite>;               // returns as soon as durable intent is recorded
  await(write: PendingWrite): Promise<EntityRef>;            // receipt + readback verified
  reconcile(write: PendingWrite): Promise<ReconcileOutcome>; // after crash/restart
  get<S>(key: Hex, schema: S): Promise<StoredEntity<S> | null>;
  query<S>(q: StoreQuery<S>): AsyncIterable<StoredEntity<S>>; // keyset pagination internally
  extend(key: Hex, expiresAt: PutRequest["expiresAt"]): Promise<EntityRef>;
  head(): Promise<{ block: bigint; timestamp: number }>;
  close(): Promise<void>;
}

export type ReconcileOutcome =
  | { state: "confirmed"; ref: EntityRef }
  | { state: "not_sent" }           // safe to submit (no broadcast evidence)
  | { state: "uncertain" }          // stop; human/ops reconciliation
  | { state: "reverted"; reason: string };
```

Typed helpers (`packages/store/src/evidence.ts`):

```ts
putBatch(store, frame: BatchFrame, opts): Promise<PendingWrite>
putDelegation(store, d: SignedDelegation, opts)
putRevocation(...); putKeygrant(...); putCheckpoint(...); putAnchorManifest(...); putAttestation(...); putReaderKey(...); putAgentProfile(...)
listBatches(store, { agentKey, lane, fromSeq?, writers?, pageSize? }): AsyncIterable<StoredEntity<"afr.batch.v1">>   // §8
groupDuplicates(batches, isValid): Promise<{ batches, equivocations: { code: "EQUIVOCATION", lane, seqFrom, keys }[] }>  // §8
listDelegations(store, agentKey), listRevocations(...), listKeygrants(store, agentKey, reader), latestCheckpoint(store, agentKey, lane), listAttestations(store, agentKey)
```

---

## 4. Batch frame format [NORMATIVE]

```
frame = CBOR( {                                   // cbor-x, deterministic (canonical) encoding, map keys sorted
  "f":   "afr.frame.v1",
  "pub": BatchPublicV1,                           // L1 §5.4, encoded as CBOR map (hex strings stay strings)
  "ct":  bytes                                    // AES-256-GCM ciphertext‖tag (L4), IV in pub.iv
} )

plaintext_of_ct = pad( deflateRaw( CBOR( {
  "headers": [ RecordHeaderV1 JCS strings ... ],  // the exact JCS strings that were hashed
  "bodies":  [ CBOR(RecordBodyV1) ... ]           // index-aligned with headers; same key sort, but JSON values allowed
                                                  // (null, negative and fractional numbers: tool/model payloads)
} ) ), bucket )

pad(x, bucket) = u32be(len(x)) ‖ x ‖ zeros(bucket − 4 − len(x))
bucket = smallest PADDING_BUCKETS value ≥ len(x)+4 (privacy 0 with padding on), else len(x)+4
payload_ct_hash = keccak256(ct)
```

- Headers are carried as **their JCS strings**, so verifiers hash exactly what was signed without re-canonicalising.
- The frame is deterministic given the same inputs and IV. The IV is chosen once and journaled (`batches.frame` stores final bytes), so a re-upload after a rollback writes identical bytes.
- Max frame: `BATCH_MAX_FRAME_BYTES` = 120 KiB. S5 measured: 120 KiB frames with all Batch attrs land (126,788 B calldata); the RPC rejects calldata above ≈ 131 KB (frames ≥ 126 KiB).

---

## 5. Arkiv schemas [NORMATIVE]

All names are lowercase snake_case. **Spike S2 (2026-11-04)** confirmed that dots (schema names) and underscores (attributes) are accepted, so no name mapping exists. Never hand-write attribute names outside `schemas.ts`.

```ts
import { addr, bool, bytes, defineSchema, str, u64 } from "@arkiv-network/sdk/schema";

export const Batch = defineSchema("afr.batch.v1", {
  agent_key:        str().indexed(),     // 0x…64
  lane:             u64().indexed(),
  seq_from:         u64().indexed(),
  seq_to:           u64().indexed(),
  chain_root:       str().indexed(),
  prev_chain_root:  str(),
  batch_root:       str(),
  session_key:      addr().indexed(),    // signer of batch_sig
  epoch_id:         u64(),
  record_count:     u64(),
  privacy:          u64(),
  // privacy ≥ 1 only (omitted at level 0):
  has_tx:            bool().indexed().optional(),
  has_block:         bool().indexed().optional(),
  has_unapproved_tx: bool().indexed().optional(),
  has_violation:     bool().indexed().optional(),
  frame:            bytes(),
});

export const Delegation = defineSchema("afr.delegation.v1", {
  agent_key:   str().indexed(),
  lane:        u64().indexed(),
  session_key: addr().indexed(),
  delegator:   addr().indexed(),         // operator or recorder identity key
  not_before:  u64(),
  not_after:   u64().indexed(),
  statement:   bytes(),                  // CBOR {message, sig, parent?: {message, sig}}
});

export const Revocation = defineSchema("afr.revocation.v1", {
  agent_key:    str().indexed(),
  session_key:  addr().indexed(),
  effective_at: u64(),
  statement:    bytes(),
});

export const AgentProfile = defineSchema("afr.agent.v1", {   // mutable: NOT readonly, NOT locked
  agent_key:   str().indexed(),
  agent_id:    str(),
  operator:    addr().indexed(),
  privacy:     u64(),
  version:     u64(),
  statement:   bytes(),                  // CBOR {profile: AgentProfile msg, sig, watched?: [...] (privacy≥1), writers: [addr], readers: [x25519], anchor: {...}}
});

export const Keygrant = defineSchema("afr.keygrant.v1", {
  agent_key: str().indexed(),
  epoch_id:  u64().indexed(),
  reader:    str().indexed(),            // x25519 pubkey hex
  kek_id:    str(),
  grant:     bytes(),                    // CBOR {enc, ct, statement: KeyGrant msg, sig}
});

export const ReaderKey = defineSchema("afr.readerkey.v1", {
  owner:   addr().indexed(),
  x25519:  str().indexed(),
  statement: bytes(),
});

export const AnchorManifest = defineSchema("afr.anchor.v1", {
  anchor_root:  str().indexed(),
  anchor_chain: u64().indexed(),
  anchor_tx:    str().indexed(),
  epoch:        u64().indexed(),         // contract's anchor counter
  leaf_count:   u64(),
  manifest:     bytes(),                 // CBOR {leaves:[...], tree dump, contract, block}
});

export const Checkpoint = defineSchema("afr.checkpoint.v1", {
  agent_key:   str().indexed(),
  lane:        u64().indexed(),
  seq_to:      u64().indexed(),
  chain_root:  str().indexed(),
  anchor_root: str().indexed(),
  anchor_tx:   str(),
  statement:   bytes(),                  // CBOR {CheckpointStatement msg, sig by anchor key, proof: bytes32[]}
});

export const Attestation = defineSchema("afr.attestation.v1", {
  agent_key:  str().indexed(),
  lane:       u64().indexed(),
  seq_to:     u64().indexed(),
  attestor:   addr().indexed(),
  verdict:    u64().indexed(),
  statement:  bytes(),                   // CBOR {Attestation msg, sig, findings_ct?}
});

export const Action = defineSchema("afr.action.v1", {   // privacy 2 only, tx-bearing actions only
  agent_key:    str().indexed(),
  lane:         u64().indexed(),
  seq:          u64().indexed(),
  action_type:  str().indexed(),
  value_bucket: u64().indexed(),         // 0:<$100 1:<$1k 2:<$10k 3:<$100k 4:≥$100k 255:unknown
  counterparty: addr().indexed().optional(),
  chain_id:     u64().indexed(),
  tx_hash:      str().indexed().optional(),
  approved:     bool().indexed(),
  record_hash:  str(),
  proof:        bytes(),                 // CBOR {sig, batch_seq_from} (Merkle proof derivable once batch stored)
});
```

**Attribute privacy rules (enforced in `putBatch`):**

| Level | Allowed batch attrs |
|---|---|
| 0 | `agent_key, lane, seq_from, seq_to, chain_root, prev_chain_root, batch_root, session_key, epoch_id, record_count, privacy, frame` |
| 1 | + `has_tx, has_block, has_unapproved_tx, has_violation` |
| 2 | level 1 + `afr.action.v1` side entities |

A unit test asserts that no other attribute can be written at each level.

---

## 6. Expiry and retention

| Strategy | Create | Maintenance |
|---|---|---|
| `upfront` | `fromDays(retention_days)`, **only if** `retention_days ≤ 30` | none |
| `rolling` (default for retention > 30 d) | `fromDays(30)` | Extension service (`apps/anchor` job): daily query `$expiresAt < now + 30d` by `createdBy(writers)`, then `extendEntity` (permissionless) to `min(created + retention, now + 90d)` |

Why (S6, ADR-013 amendment): no entity can live more than ≈ 182.5 d past its latest create/extension, and gas grows with bytes × lifetime. A 96 KiB create at > ≈ 55 d breaks the write-safety bound (2 × estimate ≤ half a block = 15M), so long retention must be built from short creates plus extensions. A 96 KiB batch costs ≈ 4.1M gas for 1 d, ≈ 27M gas for 1 y and ≈ 164M gas for 7 y (sum over the extension txs).

- Retention past the plan (litigation hold): any party can extend, thanks to `permissionlessExtension`.
- Agent profile entity: 180 days, renewed by the recorder on every start if < 60 days remain.
- Track `expiresAtBlock` in metadata. The dashboard shows "evidence expires on …".

---

## 7. Writer queue (Arkiv write safety)

One `WriterQueue` per writer account. It follows the Arkiv write-safety rules (plugin skill `arkiv-write-safety`):

```
prepare(req):
  assert frame ≤ max, attrs valid for privacy level
  [lockKey] = predictEntityKeys({ owner: writer, count: 1 })   // per-creator minting nonce
  ops = { creates: [ {schema, values, expiration, flags} ],
          ownershipChanges: req.lock ? [ { entityKey: lockKey, newOwner: EVIDENCE_LOCK_ADDRESS } ] : [] }
  calldata = SDK executeBatch(ops) through an intercepting EIP-1193 transport (S4)
  estimate = eth_estimateGas(calldata, latest)                // stop if it fails
  gas = max(1_000_000 + 400_000·(N_ops − 1), 2 × estimate); stop if gas > latest.gasLimit / 2
  nonce = getTransactionCount(latest); gasPrice = eth_gasPrice; legacy tx
  check balance ≥ gas × gasPrice and spend cap
  signed = signTransaction(build(calldata, nonce, gas, gasPrice))
  journal: state=submitting, signed_tx, tx_hash=keccak(signed), predicted_key, writer_nonce   (fsync)
submit():
  sendRawTransaction(signed)   // transport errors → stay 'submitting'; never re-sign
confirm():
  receipt = waitForTransactionReceipt(hash, timeout)
  reverted → state=failed (reason) → re-prepare later with a NEW nonce
  success  → decode EntityCreated (+ OwnershipTransferred) events; assert entityKey == predicted
           → state=receipt_confirmed
verify():
  e = getEntity(predicted, schema)
  assert bytes(e.frame) == frame, attrs == req.attrs, flags.readonly, (lock ⇒ $owner == LOCK)
  → state=verified
```

- **Single in-flight tx per writer** for simplicity. Throughput scales with more writer accounts (lanes).
- Restart: anything `submitting` → `reconcile()`: look up receipt by `tx_hash`. If unknown, check whether the nonce was consumed (`getTransactionCount(latest) > writer_nonce`). If consumed by a different tx → `uncertain` → alert ops. If not consumed → rebroadcast the **same signed bytes**.
- 401 → config error (stop). 429 → backoff, respecting `Retry-After`.
- ⚠️ The SDK's `executeBatch` returns created keys without expirations. Read `expiresAt` from events or `getEntity`.
- **Spike S4 (resolved):** the SDK exports no encoder, but it sends through a viem wallet client. The WriterQueue gives it a custom EIP-1193 transport that intercepts `eth_sendTransaction`, decodes the `execute` calldata, applies the gas/nonce rules above, signs locally, journals `keccak(signed)` and only then broadcasts. viem never retries `sendRawTransaction`. Reference implementation: `tools/spikes/guard.ts`. **Pitfall (found in P2-08):** viem's `custom` transport retries failed requests by default, which would re-enter the interceptor and sign a second time. The WriterQueue sets `retryCount: 0` and refuses a second signature within one run. Implementation: `packages/store/src/arkiv/writer-queue.ts`.
- The write-safety floor (1M + 400k per extra op ≤ half block) caps a tx at 36 ops, i.e. 18 locked creates. A 96 KiB batch is one create per tx anyway (S5).
- Out of gas (`gasUsed == gas`) is the only case where a **new** signature may follow (once, with ≥ 2× the previous gas). Every other failure is reconciled without signing.

---

## 8. Reading and pagination

```ts
async function* listBatches(store, agentKey, lane, fromSeq, writers) {   // packages/store/src/evidence.ts
  let next = fromSeq;
  const seen = new Set<Hex>();               // duplicates (rollback re-creates, forgeries) can share a seq_from
  const pin = (await store.head()).block;
  const q = (seqFrom) => store.query({
    schema: "afr.batch.v1",
    where: { agent_key: eq(agentKey), lane: eq(lane), seq_from: seqFrom },
    createdBy: writers, orderBy: { attr: "seq_from", dir: "asc" }, pageSize: 100, atBlock: pin,
  });
  while (true) {
    const page = first(100, q(gte(next)));
    if (page.length < 100) { yield* unseen(page); return; }
    // A full page is cut at its last seq_from, which is then read exhaustively: duplicates that
    // straddle the page boundary, or more than a page of spam at one seq_from, can't be skipped or stall.
    const cut = page.at(-1).attrs.seq_from;
    yield* unseen(page.filter((b) => b.attrs.seq_from < cut));
    yield* unseen(q(eq(cut)));
    next = cut + 1n;
  }
  // The caller groups duplicates by seq_from (equivocation check: groupDuplicates).
}
```

- **Keyset pagination** (by `seq_from`), not offsets, because offsets shift when entities are created.
- **Duplicates / spam:** several entities may claim the same `seq_from`, for example after a rollback re-create, or forged ones. The reader keeps only those whose `batch_sig` verifies against a valid delegation (L7). Among valid duplicates, they must be **byte-identical**. Otherwise it reports `EQUIVOCATION`, which is critical: two different signed histories.
- **Heartbeats** are ordinary one-record batches (a `note` with `meta.event = "heartbeat"`), so they need no special ordering.
- `createdBy(writers)` is a **discovery optimisation** only. Writers come from the operator-signed agent profile. The verifier can run without it (`--no-writer-filter`) to catch hidden forks.

---

## 9. Postgres implementation

Used for local dev, CI, outage fallback and self-host-without-Arkiv. It mirrors Arkiv semantics.

```sql
CREATE TABLE evidence_entities (
  key            bytea PRIMARY KEY,                 -- deterministic: keccak(schema‖idempotency_key)
  schema         text NOT NULL,
  attrs          jsonb NOT NULL,
  payload        bytea NOT NULL,
  owner          bytea NOT NULL,
  creator        bytea NOT NULL,
  readonly       boolean NOT NULL,
  permissionless_extension boolean NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  idempotency_key bytea NOT NULL UNIQUE
);
CREATE INDEX ee_batch ON evidence_entities (schema, (attrs->>'agent_key'), ((attrs->>'lane')::numeric), ((attrs->>'seq_from')::numeric));
CREATE INDEX ee_attrs ON evidence_entities USING gin (attrs jsonb_path_ops);
-- trigger: reject UPDATE of attrs/payload when readonly; reject DELETE when owner = lock address
```

- `put` is a single INSERT (idempotent on `idempotency_key`).
- **Mirror mode** (`store.mirror: postgres`): the recorder writes to the primary (Arkiv), then the mirror. The mirror is a read fallback for the dashboard and the source for re-creating entities after an Arkiv rollback.
- A Postgres store gives **no third-party guarantees** by itself. Verification relies on signatures + Base anchors, which still hold.

## 10. Memory implementation

A `Map`-based store with the same semantics: readonly enforcement, lock, expiry by a simulated block clock, `createdBy`, keyset pagination. It ships failure injection (`failNext("timeout" | "revert" | "lost_response" | "429")`) for recorder tests.

---

## 11. Conformance suite (`packages/store/test/conformance.ts`)

Runs against memory and Postgres in CI, and Arkiv testnet nightly (`ARKIV_E2E=1`).

| # | Case |
|---|---|
| C1 | put → await → get returns identical payload + attrs + flags |
| C2 | readonly: patch attempt fails |
| C3 | lock: owner = lock address. Delete attempt by writer fails |
| C4 | permissionless extension by a different account succeeds. Shortening fails |
| C5 | query by agent_key/lane/seq range with keyset pagination over 250 entities returns all, in order, no duplicates |
| C6 | createdBy filter excludes entities from other writers |
| C7 | 120 KiB frame accepted. A frame > `BATCH_MAX_FRAME_BYTES` rejected client-side before sending |
| C8 | reconcile after injected lost response → confirmed, no duplicate entity |
| C9 | privacy-level attribute allowlist enforced |
| C10 | expiry: entity not returned after expiry (memory/pg simulated; Arkiv: short-lived entity, 1-min test) |

---

## 12. Spike checklist (do first in P2, record results in `docs/04-vibecoding/SPIKES.md`)

| # | Question | How to test | Fallback |
|---|---|---|---|
| S1 | Exact SDK version + API shapes for `executeBatch`, `CreateEntityParameters`, flags option name, `ChangeOwnershipParameters` | Read installed `.d.ts` | Adjust `arkiv.ts` adapter |
| S2 | Attribute/schema-name charset (underscore, dot) | Create an entity with `seq_from` attr and schema `afr.batch.v1` | Name mapping table |
| S3 | Create + change ownership to `EVIDENCE_LOCK_ADDRESS` in **one** `executeBatch` using the predicted key | Testnet script | Two txs (create, then transfer) with a short unlocked window; or no lock (ADR-011 fallback) |
| S4 | Can we sign Arkiv txs offline (get raw bytes before broadcast)? | Look for exported encoder | Nonce-based reconciliation |
| S5 | `bytes` total limit, measured: largest frame + attrs accepted | Binary search with real attrs | Lower `BATCH_MAX_FRAME_BYTES` |
| S6 | Gas/tGLM cost per 96 KiB batch for 1 day / 1 year / 7 years | Testnet receipts | Feed cost model |
| S7 | `createdBy` + `orderBy(seq_from)` + `gte` query works and how fast it is at 10k entities | Load script | Index on fewer attrs |
| S8 | Rate limits with an access key (writes/min, queries/min) | Load script | Batch bigger, more writers |
| S9 | Readonly entity: is `extendEntity` by non-owner allowed with `permissionlessExtension`? Can a locked entity still be extended? | Testnet | Plan ADR-012/013 adjustments |
| S10 | Does `watchEntityEvents` deliver reliably for our schemas? | Run 1 h | Polling queries |

---

## 13. File layout

```
packages/store/
├─ src/
│  ├─ index.ts
│  ├─ types.ts               # EvidenceStore, PutRequest, ...
│  ├─ schemas.ts             # defineSchema(...) for all kinds (§5)
│  ├─ privacy.ts             # attr allowlists per level
│  ├─ frame.ts               # encode/decode/pad (§4)
│  ├─ evidence.ts            # typed helpers (§3)
│  ├─ arkiv/
│  │  ├─ client.ts           # chain + clients factory (rabdi, localhost, mainnet later)
│  │  ├─ store.ts            # ArkivStore implements EvidenceStore
│  │  ├─ writer-queue.ts     # §7
│  │  └─ errors.ts           # map SDK/RPC errors → StoreError kinds
│  ├─ postgres/
│  │  ├─ schema.sql
│  │  └─ store.ts
│  └─ memory/store.ts
└─ test/
   ├─ conformance.ts
   ├─ frame.test.ts
   ├─ privacy.test.ts
   └─ arkiv.e2e.test.ts      # gated by ARKIV_E2E=1
```

---

## 14. Vibecoding prompts

1. "Install `@arkiv-network/sdk` at an exact version (`pnpm add -E`). Write `tools/spikes/arkiv-*.ts` scripts for S1–S10 in L3 §12, using the Rabdi testnet with `ARKIV_ACCESS_KEY` and a funded `AFR_ARKIV_WRITER_KEY`. Print results as a markdown table. Don't build the store yet."
2. "Create `packages/store` with `types.ts` and `schemas.ts` from L3 §3/§5, adjusted per `SPIKES.md`. Add `privacy.ts` allowlists and a test that every schema has ≤ 31 attributes and every name ≤ 32 bytes, lowercase."
3. "Implement `frame.ts` per L3 §4 with cbor-x deterministic encoding, fflate `deflateSync` raw, and bucket padding. Round-trip tests + max-size property test."
4. "Implement `MemoryStore` with failure injection, then the conformance suite (L3 §11). Make MemoryStore pass it."
5. "Implement `PostgresStore` (schema.sql with readonly/lock triggers) and make it pass conformance using testcontainers."
6. "Implement `ArkivStore` + `WriterQueue` per L3 §7 with durable state callbacks (the recorder journal persists state; the queue takes a `persist(state)` hook). Make the conformance suite pass against Rabdi with `ARKIV_E2E=1`."
7. "Implement `listBatches` keyset pagination with duplicate/equivocation detection (L3 §8)."
