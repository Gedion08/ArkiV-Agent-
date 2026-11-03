# Phase P0 — Foundations (≈ 3 days)

**Goal:** a monorepo where an AI coding agent can work safely: conventions, CI, layer rules, a test-vector harness and a local stack skeleton. **No product code yet.**

| | |
|---|---|
| Entry criteria | Docs in `docs/` reviewed. GitHub repo created. Node 22.10+, pnpm 9+, Foundry, Docker installed |
| Exit criteria | `pnpm i && pnpm verify` passes on a clean clone. CI green. `pnpm local:up` starts Postgres + Anvil. Empty packages compile |
| Layers touched | L11 (infra), skeleton of all packages |

---

## Tickets

| ID | Task | Files | Done when |
|---|---|---|---|
| P0-01 | Init repo: pnpm workspaces, Turborepo, `tsconfig.base.json` (strict, ESM, `moduleResolution: bundler`, `noUncheckedIndexedAccess`), Biome, `.editorconfig`, `.nvmrc` (22) | root | `pnpm build` no-ops successfully |
| P0-02 | Create empty packages/apps per Architecture §16, each with `package.json` (`"type":"module"`, exports map), `src/index.ts`, `test/smoke.test.ts` | `packages/*`, `apps/*` | `pnpm test` runs one smoke test per package |
| P0-03 | dependency-cruiser with layer rules (Architecture §3) | `.dependency-cruiser.cjs` | Importing `apps/*` from `packages/*` fails CI |
| P0-04 | Changesets + versioning policy | `.changeset/` | `pnpm changeset` works |
| P0-05 | Foundry project init in `contracts/` with OZ 5.x | `contracts/` | `forge test` passes (empty) |
| P0-06 | `packages/test-vectors` skeleton: `vectors/` dir, `gen` script stub, README explaining immutability | | |
| P0-07 | Docker Compose: postgres, anvil, mailpit, localstack | `infra/compose/` | `pnpm local:up` / `local:down` |
| P0-08 | CI workflows `ci.yml`, `security.yml` (L11 §3) | `.github/workflows/` | Green on main |
| P0-09 | `CLAUDE.md` at repo root (copy from this docs repo, adjusted) + `docs/` copied into the repo | root | Agent reads it at session start |
| P0-10 | `SECURITY.md`, `LICENSE` (Apache-2.0 for packages; commercial notice for apps), `CONTRIBUTING.md` | root | |
| P0-11 | Logging: create `packages/log` (a `pino` wrapper with redaction + a canary test helper). It's a separate package because `packages/core` must stay pure | `packages/log` | Canary test helper exported |
| P0-12 | Lint rules: ban `JSON.stringify` in files under `packages/core/src/record/**` and `packages/store/src/frame.ts` (Biome `noRestrictedImports`/grit or a custom script) | `tools/lint/` | CI check |

## Conventions locked in this phase

- ESM only. Named exports. No default exports (except Next.js pages).
- Errors: typed error classes with `code` strings (`AfrError { code, message, cause }`). Never put secrets in messages.
- Bigint for uint64 in code. Decimal strings at JSON boundaries.
- Hex: lowercase `0x` strings, typed `Hex` from viem.
- Tests next to the package under `test/`. Fixtures under `test/fixtures/`.
- Commit messages: Conventional Commits. PR template with a "Which docs section does this implement?" field.

## Vibecoding script (paste in order)

1. "Read `CLAUDE.md`, `docs/01-architecture/ARCHITECTURE.md` §3, §15, §16 and `docs/03-phases/P0-foundations.md`. Implement P0-01 and P0-02 only. Show me the tree when done."
2. "Implement P0-03 (dependency-cruiser layer rules) and prove it works with a deliberately bad import that you then remove."
3. "Implement P0-05 to P0-08."
4. "Implement P0-10 to P0-12."

## Risks

- Over-engineering the skeleton → time-box to 3 days. Anything not in the tickets waits.
