# Changesets

Run `pnpm changeset` in every PR that changes a published package (`packages/*`).

Versioning policy (Architecture §17):

- Packages are semver. `0.x` until the record format is frozen at the end of P5.
- Any change to a hashed format, domain string, EIP-712 type or schema name is a **major** bump
  and needs an ADR plus new test vectors (`packages/test-vectors`). Old vectors are never edited.
- Apps (`apps/*`) are private and versioned by release tag, not changesets.
