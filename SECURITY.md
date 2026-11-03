# Security policy

AFR stores signed, encrypted evidence for agents that move money. Weaknesses in record formats,
signatures, encryption or the watcher are treated as critical.

## Reporting

Do **not** open a public issue. Use GitHub private vulnerability reporting
(Security → Report a vulnerability) on this repository. We aim to acknowledge within 2 business
days and give a fix timeline within 7.

## Scope

- `packages/core`, `packages/crypto`, `packages/verifier`: format, hashing, signing, encryption bugs
- `contracts/`: `RecorderAnchor` and the kill-switch module
- Recorder/proxy paths that could leak plaintext or keys, or drop records silently
- Watcher bypasses (an unlogged transaction that raises no alert)

Out of scope: testnet faucets, third-party services (Arkiv, Base, ERC-8004 registries) except
how AFR uses them.

## Handling secrets in this repo

Never commit keys, tokens or `.env` files. CI runs gitleaks on every PR. Local stack credentials
in `infra/compose/` are for local development only.
