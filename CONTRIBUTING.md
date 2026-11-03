# Contributing

Read `CLAUDE.md` first: its hard rules apply to humans and coding agents alike.

## Setup

Node 22.10+ (`.nvmrc`), pnpm (version pinned in `package.json`), Foundry, Docker.

```bash
pnpm i
pnpm verify            # lint + layer rules + typecheck + tests + vectors + build
pnpm local:up      # postgres, anvil, mailpit, localstack
forge test --root contracts
```

## Workflow

- One phase ticket per branch and PR (`docs/03-phases/`). The PR names the doc sections it implements.
- Conventional Commits (`feat(core): …`, `fix(store): …`).
- Add a changeset (`pnpm changeset`) when a published package changes.
- Update `docs/04-vibecoding/PROGRESS.md` when a ticket is done.

## Rules CI enforces

- Biome lint/format, no default exports.
- Layer dependency rule (`.dependency-cruiser.cjs`, Architecture §3).
- No `JSON.stringify` in hashed-format code (`tools/lint/no-json-stringify.mjs`).
- Committed test vectors never change.
- Contracts: `forge fmt`, tests, gas snapshot.

Changes to `packages/core`, `packages/crypto` or `contracts/` need two reviews.
