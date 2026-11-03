# Phase P7 — Scale & Enterprise (weeks 23–40)

**Goal:** win enterprise and regulated fintech deals. Self-hosting, Solana, SSO, EU data residency, SOC 2 Type II, high-scale throughput.

| | |
|---|---|
| Entry | v1 GA with paying customers |
| Exit | ≥ 1 enterprise/self-host customer. SOC 2 Type II window started. Solana in production for ≥ 1 customer. 10k agents load-tested |

---

## Workstreams

### 7A — Self-hosting
| ID | Task |
|---|---|
| P7-01 | Helm chart (all services, external Postgres, KMS abstraction: AWS/GCP/Vault Transit) |
| P7-02 | Docker Compose "single box" edition + upgrade/migration tooling |
| P7-03 | Private anchor option: customer key + own `RecorderAnchor` deployment or allowlisting on ours. `anchor()` single-agent path (ANC-06) |
| P7-04 | Air-gapped mode (PostgresStore + periodic egress-only anchoring relay) |
| P7-05 | Licensing/feature flags for commercial self-host |

### 7B — Solana & more chains
| P7-06 | Solana recorder hook (`@solana/kit` sign/send wrappers) + record conventions (L6 §8) |
| P7-07 | Solana watcher (Yellowstone gRPC or provider webhooks), SPL outflow detection |
| P7-08 | Additional EVM L2s on demand. Chain registry config |

### 7C — Enterprise features
| P7-09 | SSO (OIDC/SAML) + SCIM provisioning |
| P7-10 | EU region (control-plane data residency). Org-level region pinning |
| P7-11 | Advanced RBAC: per-agent roles, approval groups, four-eyes rules |
| P7-12 | PagerDuty/Opsgenie, SIEM export (Splunk/Datadog) of **metadata** alerts |
| P7-13 | ERP/AP agent connectors (approval workflows integrated with finance systems) |

### 7D — Scale & reliability
| P7-14 | Load test: 10k agents, 1k actions/s aggregate. Shard the watcher by chain/tenant. Optimise the anchor rollup (≥ 5k leaves) |
| P7-15 | Multi-writer per tenant (lanes ↔ writer accounts) automation and GLM balance management |
| P7-16 | Recorder attestation: reproducible builds + signed binaries. Optional TEE (AWS Nitro Enclaves / Intel TDX) recorder mode where enclave attestations bind session keys |
| P7-17 | Arkiv mainnet migration (when available): dual-write period, verifier support for both networks, evidence continuity via Base anchors |

### 7E — Compliance
| P7-18 | SOC 2 Type II. ISO 27001 gap analysis |
| P7-19 | DORA third-party ICT provider documentation pack for EU financial customers |

## Notes for vibecoding

- Self-hosting forces config discipline. Every service must start from env/config only, with no hidden AFR-cloud dependency. Add a CI job that runs the full stack in `--self-host` mode.
- TEE mode is research-heavy. Do a spike document first (`docs/04-vibecoding/SPIKES.md`) before any code.
