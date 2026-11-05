# L8 — Platform API, Tenancy, Notifications & Billing (`apps/api`)

| | |
|---|---|
| App | `apps/api`: Fastify HTTP API + pg-boss workers (notifier, metering, digests) |
| Depends on | `@afr/core`, `@afr/store` (read), `@afr/identity`, Fastify, Zod, `fastify-type-provider-zod`, `@fastify/swagger`, Drizzle ORM, Postgres 16, pg-boss, `siwe`, Stripe, Resend/SES, Slack Web API, Telegram Bot API |
| Generated | `packages/client` (typed client from OpenAPI) |
| Requirements | PLT-01…PLT-05, DSH-01, DSH-09, WAT-07, PRV-07 |
| Phase | P2 (orgs/agents/recorder keys/checkpoints), P4 (alerts, notifications, auth for dashboard), P6 (grants, policies, approvals API, billing, public API), P7 (SSO, EU region) |

---

## 1. Principles

- **No plaintext, ever.** The API stores public data, metadata, HMAC commitments, wrapped watch keys (KMS) and wrapped keygrants. Request schemas reject fields named `body`, `args`, `result`, `context`, `plaintext`.
- **Tenancy at the query layer.** Every table carries `org_id` (or reaches it through `agents`). Every repository function takes `ctx.orgId` and adds it to `WHERE`. Postgres RLS is the second line of defence: `inOrg(pool, orgId, fn)` runs one transaction as the `afr_app` role with `app.org_id` set (`SET LOCAL ROLE` + `set_config(..., true)`), and policies on every tenant table hide and refuse other orgs' rows. System lookups that must cross orgs (session, recorder-key and invitation-token auth, a user's own org list, org creation) run as the owner role, which RLS doesn't apply to.
- **Contract-first.** Zod schemas generate OpenAPI 3.1, which generates the typed client.
- **Idempotent writes** via the `Idempotency-Key` header on POSTs.

---

## 2. Authentication and authorisation

| Principal | Auth | Scope |
|---|---|---|
| Dashboard user | SIWE (EIP-4361; EOAs verify locally, ERC-1271 / ERC-6492 wallets through the API's `siweClient` on the message's chain) → session cookie (`__Host-afr`, httpOnly, Secure, SameSite=Strict, 12 h) + CSRF token header | org memberships |
| Recorder | `Authorization: Bearer afr_rk_<id>_<secret>` + `X-AFR-Signature: hex(HMAC-SHA256(sha256(secret), METHOD \n path \n ts \n hex(sha256(body))))` + `X-AFR-Timestamp` (unix seconds, ±5 min). `<id>` is 16 hex chars, `<secret>` 64; `path` includes the query string; the API stores only `sha256(secret)` | one agent (+ lanes) |
| Service (anchor, watcher) | mTLS inside the VPC + service JWT (short-lived, KMS-signed) | per service |
| Public | none, rate-limited | `/v1/public/*` |
| API user (v1) | org API key `afr_ok_…` | org, role-limited |
| SSO (P7) | OIDC/SAML via WorkOS or similar | org |

**Roles:** `owner` (billing, delete org), `admin` (agents, members, grants), `engineer` (agents, keys, alerts), `viewer` (read), `auditor` (read assigned agents only, no settings). Assignments live in `agent_auditors` (owner/admin, §4.3): an auditor's agent list holds only assigned agents, any other agent is 404, and the member and invitation lists are 403. Changing a member's role away from `auditor`, or removing them, drops their assignments.

| Action | owner | admin | engineer | viewer | auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| Manage billing / delete org | ✅ | | | | |
| Members, roles | ✅ | ✅ | | | |
| Create/edit agents, recorder keys | ✅ | ✅ | ✅ | | |
| Grants (auditor access) | ✅ | ✅ | | | |
| Policies (v1) | ✅ | ✅ | ✅ (draft) | | |
| Ack/resolve alerts | ✅ | ✅ | ✅ | | |
| Read timeline (decrypt needs a reader key anyway) | ✅ | ✅ | ✅ | ✅ | assigned |

---

## 3. Database schema (Drizzle; abbreviated DDL)

> The API uses raw SQL migrations over `pg` (`apps/api/src/db/migrations.ts`) with the tables needed so far, plus `sessions`, `siwe_nonces`, `tx_intents`, `orgs.dek_wrapped` (§8) and `agent_auditors(org_id, agent_id, user_id, added_by, added_at)` (§2). Drizzle and pg-boss arrive with the tickets that need them.

```sql
-- tenancy
CREATE TABLE orgs (id uuid PK DEFAULT gen_random_uuid(), name text NOT NULL, plan text NOT NULL DEFAULT 'developer',
  region text NOT NULL DEFAULT 'us', stripe_customer_id text, created_at timestamptz DEFAULT now());
CREATE TABLE users (id uuid PK, wallet bytea UNIQUE NOT NULL, email text, display_name text, created_at timestamptz);
CREATE TABLE memberships (org_id uuid REFERENCES orgs, user_id uuid REFERENCES users, role text NOT NULL,
  PRIMARY KEY (org_id, user_id));
CREATE TABLE invitations (id uuid PK, org_id uuid, email text, wallet bytea, role text, token_hash bytea, expires_at timestamptz);

-- agents
CREATE TABLE agents (
  id uuid PK, org_id uuid NOT NULL REFERENCES orgs,
  agent_id text NOT NULL UNIQUE, agent_key bytea NOT NULL UNIQUE,
  name text NOT NULL, operator bytea, privacy_level smallint NOT NULL DEFAULT 0,
  retention_days int NOT NULL DEFAULT 365, expiry_strategy text NOT NULL DEFAULT 'rolling',
  approval_threshold_cents bigint, watch_grace_s int NOT NULL DEFAULT 60,
  anchor_cadence_s int NOT NULL DEFAULT 600, status text NOT NULL DEFAULT 'active',  -- active|paused|archived
  profile_version bigint NOT NULL DEFAULT 0, profile_entity bytea,
  kill_switch jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz, updated_at timestamptz);
CREATE TABLE agent_lanes (agent_id uuid REFERENCES agents, lane int, writer bytea, last_seq numeric, last_chain_root bytea,
  last_batch_at timestamptz, last_heartbeat_at timestamptz, recorder_version text, PRIMARY KEY (agent_id, lane));
CREATE TABLE recorder_keys (id text PK, org_id uuid, agent_id uuid, secret_hash bytea NOT NULL, lanes int[] NOT NULL,
  created_by uuid, created_at timestamptz, last_used_at timestamptz, revoked_at timestamptz);
CREATE TABLE watch_keys (agent_id uuid PK REFERENCES agents, kms_ciphertext bytea NOT NULL, prev_kms_ciphertext bytea, created_at timestamptz, rotated_at timestamptz);
CREATE TABLE watched_addresses (id uuid PK, org_id uuid, agent_id uuid, chain_id bigint, address bytea, kind text,
  since_block bigint, source text, created_at timestamptz, UNIQUE (agent_id, chain_id, address));
CREATE TABLE session_keys (agent_id uuid, lane int, address bytea, not_before timestamptz, not_after timestamptz,
  delegation_entity bytea, revoked_at timestamptz, presigned_revocation_kms bytea, PRIMARY KEY (agent_id, address));

-- evidence index (public data mirror for fast UI)
CREATE TABLE batches_index (agent_id uuid, lane int, seq_from numeric, seq_to numeric, entity_key bytea, arkiv_tx bytea,
  chain_root bytea, batch_root bytea, record_count int, flags smallint, epoch_id int, bytes int, created_at timestamptz,
  PRIMARY KEY (agent_id, lane, seq_from));
CREATE TABLE checkpoints (id uuid PK, agent_id uuid, lane int, seq_to numeric, chain_root bytea, batch_entity bytea,
  status text CHECK (status IN ('pending','validated','anchored','superseded','rejected')),
  anchor_epoch bigint, anchor_tx bytea, anchor_root bytea, proof bytea[], checkpoint_entity bytea, reject_reason text,
  received_at timestamptz, anchored_at timestamptz,
  UNIQUE (agent_id, lane, seq_to));

-- readers & grants
CREATE TABLE reader_keys (id uuid PK, org_id uuid, owner_wallet bytea, x25519 bytea UNIQUE, label text,
  statement jsonb, entity_key bytea, not_after timestamptz, revoked_at timestamptz);
CREATE TABLE agent_readers (agent_id uuid, reader_id uuid, role text CHECK (role IN ('operator','auditor')),
  from_epoch int, to_epoch int, added_by uuid, added_at timestamptz, removed_at timestamptz, PRIMARY KEY (agent_id, reader_id));
CREATE TABLE grants (id uuid PK, agent_id uuid, reader_id uuid, epoch_id int, keygrant_entity bytea, granted_by uuid, granted_at timestamptz,
  shredded_at timestamptz);

-- alerts & notifications
CREATE TABLE alerts (id uuid PK, org_id uuid, agent_id uuid, lane int, type text, severity text, dedupe_key text,
  status text, resolution text, subject jsonb, evidence jsonb, count int DEFAULT 1,
  first_seen_at timestamptz, last_seen_at timestamptz, acked_by uuid, resolved_by uuid, UNIQUE (org_id, dedupe_key));
CREATE TABLE alert_events (id bigserial PK, alert_id uuid, kind text, actor text, data jsonb, at timestamptz);
CREATE TABLE notification_channels (id uuid PK, org_id uuid, kind text CHECK (kind IN ('webhook','email','slack','telegram','pagerduty')),
  config_kms bytea NOT NULL, min_severity text, agent_filter uuid[], enabled boolean, created_at timestamptz);
CREATE TABLE deliveries (id bigserial PK, channel_id uuid, alert_id uuid, status text, attempts int, last_error text, at timestamptz);

-- guardrails (v1)
CREATE TABLE policies (id uuid PK, org_id uuid, agent_id uuid, version int, doc jsonb, doc_hash bytea, status text
  CHECK (status IN ('draft','active','archived')), created_by uuid, activated_at timestamptz, UNIQUE (agent_id, version));
CREATE TABLE approvals (id uuid PK, org_id uuid, agent_id uuid, lane int, request_seq numeric, request_hash bytea,
  summary jsonb,   -- optional, opt-in: recorder-supplied human summary (may contain sensitive data → encrypted to approvers, see L10)
  status text, method text, approver text, signature bytea, attestation_sig bytea, expires_at timestamptz, decided_at timestamptz);

-- usage & billing
CREATE TABLE usage_events (id bigserial PK, org_id uuid, agent_id uuid, kind text, qty numeric, unit text, at timestamptz);
  -- kinds: actions, batches, bytes_stored_days, anchors_share, extensions, packs, verifications
CREATE TABLE usage_daily (org_id uuid, agent_id uuid, day date, kind text, qty numeric, PRIMARY KEY (org_id, agent_id, day, kind));

-- audit
CREATE TABLE audit_log (id bigserial PK, org_id uuid, actor text, action text, target text, data jsonb, ip inet, at timestamptz);
```

---

## 4. REST API (v1 paths; full OpenAPI generated)

### 4.1 Auth

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/auth/nonce` | SIWE nonce |
| POST | `/v1/auth/siwe` | `{message, signature}` → session |
| POST | `/v1/auth/logout` | |
| GET | `/v1/me` | user + memberships |

### 4.2 Orgs, members

`GET/POST /v1/orgs`, `GET/PATCH /v1/orgs/{org}`, `GET/POST/DELETE /v1/orgs/{org}/members`, `GET/POST /v1/orgs/{org}/invitations`, `DELETE /v1/orgs/{org}/invitations/{id}`, `POST /v1/invitations/accept`.

- `POST /members {wallet, role}` adds a wallet or changes a member's role. `DELETE /members/{userId}`: owner/admin, or a member leaving. Only an owner grants, demotes or removes `owner`, and the last owner stays (409 `LAST_OWNER`).
- Invitations: `{role, wallet?, email?}` → `afr_inv_<64 hex>` (shown once, only its sha256 stored, 7 days, single use). A `wallet` binds it to that signer; accepting as anyone else is 404. An existing member keeps their role. With an `email` and a configured mailer (SMTP), the API sends `{dashboardOrigin}/invite#<token>` after commit; the token is in the fragment so it never reaches a server log. The response says `email_sent`, and a failed send leaves the invitation valid (logged by error code only). `GET` lists pending invitations (owner/admin, never the token); `DELETE` revokes one (audited), after which accepting is 404.

### 4.3 Agents

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/v1/orgs/{org}/agents` | create: `{agent_id \| register: {...}, name, privacy_level, retention_days, ...}` → also provisions the watch key (returned **once**, for the recorder config) |
| GET/PATCH | `/v1/agents/{id}` | settings (`name`, `status`, `approval_threshold_cents`, `watch_grace_s` 15–600). Privacy/retention changes require a new signed AgentProfile (`profile_statement` in the body) |
| POST | `/v1/agents/{id}/watch-key/rotate` | → `{watch_key}` (shown once; put it in the recorder config). The previous key is kept so the watcher still matches intents committed under it. Only one previous key is kept |
| POST | `/v1/agents/{id}/recorder-keys` | → `afr_rk_…` (shown once) |
| DELETE | `/v1/agents/{id}/recorder-keys/{keyId}` | |
| GET/POST/DELETE | `/v1/agents/{id}/watched-addresses` | `{chain_id, address, kind: eoa\|smart_account\|safe\|session_key, since_block?}`; re-adding returns the existing row (200) |
| GET/POST/DELETE | `/v1/agents/{id}/auditors` | owner/admin. `POST {user_id}`: the member must have role `auditor` (else 409 `NOT_AN_AUDITOR`); idempotent. `DELETE /auditors/{userId}` |
| GET | `/v1/agents/{id}/lanes` | status per lane |
| GET | `/v1/agents/{id}/batches?lane&from_seq&limit` | public index (UI convenience, verifiable against Arkiv); `limit` ≤ 500, cursor `next_from_seq` |
| GET | `/v1/agents/{id}/checkpoints?lane&after_seq&limit` | cursor `next_after_seq` |
| GET | `/v1/agents/{id}/registration` | proposed ERC-8004 registration JSON with the AFR entry |
| POST | `/v1/agents/{id}/kill-switch/test` | dry-run the kill-switch actions |

### 4.4 Recorder endpoints (recorder auth)

| Method | Path | Body |
|---|---|---|
| POST | `/v1/recorder/heartbeat` | L2 §10 |
| POST | `/v1/recorder/intents` | `{items: [{lane, seq, chain_id, tx_commit?, nonce_commit}]}` → forwarded to the watcher (`NOTIFY`) |
| POST | `/v1/recorder/checkpoints` | `{lane, seq_from, seq_to, batch_root, chain_root, entity_key, arkiv_tx}` |
| POST | `/v1/recorder/delegations` | `{lane, session_key, not_before, not_after, entity_key, presigned_revocation?}` |
| GET | `/v1/recorder/config` | `{readers: [x25519…], policy: {version, doc_hash, doc}, approval_threshold_cents, privacy_level, anchored: [{lane, seq_to, epoch, anchor_tx, chain_root}]}`. ETag-cached, polled every 60 s. `anchored` is the latest anchored checkpoint per lane of the key; the recorder marks its batches ≤ `seq_to` anchored (P3-06) |
| POST | `/v1/recorder/approvals` | (v1) create an approval request → returns the id. Long-poll `GET /v1/recorder/approvals/{id}` |

### 4.5 Alerts

`GET /v1/orgs/{org}/alerts?status&severity&agent&type`, `GET /v1/alerts/{id}`, `POST /v1/alerts/{id}/ack`, `POST /v1/alerts/{id}/resolve {resolution, note}`, `POST /v1/alerts/{id}/suppress {until}`.

### 4.6 Notifications

`GET/POST/PATCH/DELETE /v1/orgs/{org}/channels`, `POST /v1/channels/{id}/test`. Slack OAuth install: `GET /v1/integrations/slack/install` → callback. Telegram: bot deep link `t.me/afr_bot?start=<token>`.

### 4.7 Readers and grants (v1)

`GET/POST /v1/orgs/{org}/reader-keys` (statement + sig required), `POST /v1/agents/{id}/readers {reader_id, role, from_epoch?}`, `DELETE /v1/agents/{id}/readers/{reader}` (triggers early epoch rotation on next recorder config poll), `POST /v1/agents/{id}/grants {reader_id, epochs:[…], keygrant_entities:[…]}` (records grants the browser already published), `POST /v1/agents/{id}/shred {epoch_id}`.

### 4.8 Policies and approvals (v1)

`GET/POST /v1/agents/{id}/policies`, `POST /v1/policies/{pid}/activate`, `POST /v1/policies/{pid}/dry-run` (runs in the browser; the API stores the result only), `GET /v1/orgs/{org}/approvals?status=pending`, `POST /v1/approvals/{id}/decide {decision, method, signature?}`.

### 4.9 Public

`GET /v1/public/agents/{agentId}/summary` (trust summary, cached), `GET /v1/public/agents/{agentId}/badge.svg`, `GET /v1/public/anchors/{epoch}`.

### 4.10 Webhooks (outbound)

```
POST <customer url>
X-AFR-Event: alert.opened | alert.resolved | anchor.confirmed | approval.requested
X-AFR-Delivery: <uuid>
X-AFR-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>
{ "type": "alert.opened", "alert": { …Alert (L6 §6.1)… }, "agent": { "id", "agent_id", "name" } }
```

Retries: 10 attempts over 24 h with exponential backoff. Deliveries are logged.

---

## 5. Workers (pg-boss queues)

| Queue | Producer | Consumer | Notes |
|---|---|---|---|
| `notify` | watcher alert engine, approvals | notifier | Per-channel adapters, rate-limited (Slack 1/s/channel) |
| `checkpoint.validated` | API | anchor service | v0: `checkpoints.status` polled by the anchor service (L5 §3.4), no queue |
| `anchor.confirmed` | anchor service | API → recorder notices (via config poll) + webhooks | v0: the anchor service writes `checkpoints` directly; recorders see it in `/v1/recorder/config`. Webhooks later |
| `usage.rollup` | cron hourly | metering | `usage_events` → `usage_daily` → Stripe meter events |
| `digest.weekly` | cron | email | Only metadata (counts, alerts, verify status). Value summaries need the browser |
| `profile.renew` | cron daily | API | Reminds operators (agent profile expiry, identity key expiry) |

### 5.1 Notifier adapters

- **Email:** Resend/SES with templates. Critical alerts are sent individually, others as a digest.
- **Slack:** app with `chat:write` and interactive buttons (Ack / Open / Approve v1). Signature verification on interactions.
- **Telegram:** bot. Chats link through a one-time token. Inline keyboard for ack/approve.
- **Webhook:** §4.10.
- **PagerDuty** (P7): Events API v2.

---

## 6. Metering and billing (v1)

| Meter | Source | Unit |
|---|---|---|
| `active_agents` | agents with a heartbeat in the period | agent-month |
| `actions` | checkpoint record counts | 1k actions |
| `storage` | `Σ batch bytes × retention days` at creation | GB-day (cost-plus) |
| `anchors` | per-agent share or dedicated | anchor |
| `packs` | exports | pack |
| `seats` | auditor seats | seat-month |

Stripe Billing: products/prices per plan + metered prices. Customer portal for invoices. Plan limits are enforced softly: a warning at 80 %, overage at 100 %. **Never stop recording for billing reasons.** Recording is evidence. Only dashboard features get limited.

---

## 7. Rate limits

| Principal | Limit |
|---|---|
| Recorder | 50 req/s per key (burst 200: 200 per 4 s). Counted after auth, so forged requests can't spend a key's budget. Intents are batched (≤ 100 per call) |
| Dashboard session | 20 req/s |
| Public | 5 req/s per IP. Summary is cached for 5 min |
| Auth nonce, SIWE login | 10/min per IP |

Counters live in Redis (`ApiOptions.redis`, namespace `afr-rl:`), so every API instance shares one budget. If Redis is down, limiting is skipped rather than failing requests. Without Redis (dev), each instance counts alone.

---

## 8. Security requirements

- Input validation via Zod on every route. Unknown fields are rejected (`.strict()`).
- Secrets (channel configs, watch keys, pre-signed revocations) are encrypted with KMS envelope keys per org (`@afr/secrets`, shared with the watcher): each org's random AES-256 DEK is stored only wrapped by the KEK (`kmsKeyWrapper`: KMS `Encrypt`/`Decrypt` with encryption context `{afr_org}`; `localKeyWrapper` for dev), and secrets are sealed `0x01 ‖ iv ‖ AES-GCM(dek, iv, plain, aad)` with the agent key or session key as AAD. Unwrapped DEKs are cached LRU (default 1000 orgs) for 15 min, and evicted keys are zeroed. `migrateLegacySecrets` re-seals pre-v2 data (`iv ‖ AES-GCM(master)` under the old single master key) into this format. It is idempotent and leaves rows that changed meanwhile untouched.
- Audit log for every mutation: who, what, from which IP.
- CSRF: double-submit token + SameSite=Strict.
- CORS: `@fastify/cors`, only `ApiOptions.dashboardOrigin` (exact match, with credentials). Without one, no CORS headers.
- Security headers via `@fastify/helmet`.
- Dependency pinning, SBOM in CI.
- PII minimisation: email is optional, the wallet is the identity.

---

## 9. File layout

```
apps/api/
├─ src/
│  ├─ server.ts            # fastify bootstrap, plugins (auth, tenancy, rate-limit, swagger)
│  ├─ db/schema.ts         # drizzle tables (§3) + migrations/
│  ├─ auth/{siwe,session,recorder,service}.ts
│  ├─ routes/{orgs,agents,recorder,alerts,channels,readers,grants,policies,approvals,public}.ts
│  ├─ services/*.ts        # business logic, all take ctx {orgId, actor}
│  ├─ workers/{notify,usage,digest,renew}.ts
│  ├─ notify/{email,slack,telegram,webhook}.ts
│  └─ openapi.ts           # emits openapi.json for packages/client
└─ test/                   # vitest + testcontainers postgres; tenancy isolation tests
```

## 10. Tests and acceptance criteria

| # | Test |
|---|---|
| P1 | Tenancy: for every list/get route, a user of org B gets 404 for org A objects (generated test over the route table) |
| P2 | Recorder HMAC auth: replayed request (> 5 min) rejected. Body tamper rejected |
| P3 | Plaintext guard: a request with forbidden field names → 400 |
| P4 | Webhook signatures verify with the documented algorithm (sample code in docs) |
| P5 | Idempotency: duplicate POST checkpoint with the same key → single row |
| P6 | Billing never blocks recorder endpoints, even for an unpaid org |
| P7 | OpenAPI generated, client compiles, no `any` |

## 11. Vibecoding prompts

1. "Create `apps/api` with Fastify + Zod type provider + swagger, Drizzle schema for §3 (start with tenancy, agents, recorder_keys, agent_lanes, checkpoints, batches_index), migrations, testcontainers tests. Implement SIWE auth and sessions."
2. "Implement the recorder endpoints in §4.4 with HMAC auth (§2) and idempotency. Tests P2, P5."
3. "Implement alerts + notification channels + the notifier worker with email and webhook adapters (§4.5, §4.6, §4.10, §5). Tests P4."
4. "Add the tenancy isolation generated test P1 and the plaintext guard P3."
5. "(v1) Add readers/grants/policies/approvals routes, Slack and Telegram adapters, Stripe metering (§6)."
