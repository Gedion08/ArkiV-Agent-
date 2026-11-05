# fr: verify an AI agent's flight recorder

`fr` checks an agent's evidence: the signed, hash-chained records it published on Arkiv, the anchors on Base, and the agent's ERC-8004 registration. You need nothing from the agent's operator and no AFR account.

## Verify an agent in 60 seconds

1. **Get the CLI** (Node ≥ 22.10). `@afr/cli` isn't on the npm registry yet. Its tarballs are on this repo's GitHub Release, so `npx` runs it directly:
   ```bash
   alias fr="npx --yes https://github.com/Gedion08/ArkiV-Agent-/releases/download/cli-v0.1.0/afr-cli-0.1.0.tgz"
   ```
   The release also has a `SHA256SUMS` file. To build from source instead, use `pnpm i && pnpm --filter @afr/cli... build`, then `alias fr="node $PWD/apps/cli/dist/cli.js"`.
2. **Get an Arkiv access key** from the Arkiv Hub. It only needs to read.
   ```bash
   export ARKIV_ACCESS_KEY=…
   ```
3. **Verify the demo agent:**
   ```bash
   fr verify agent eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:10588
   ```

You should see something like this:

```text
identity      eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:10588
lane 0        8 records · 2 batches · seq 0…7
anchors       last epoch 3 · seq_to 6 · 2026-11-04T21:50:02.000Z
unanchored    1 records
ℹ UNANCHORED_TAIL lane 0: 1 records after the last anchor
RESULT: PASS (structural)   — run with --reader-key for full verification
```

## What this checked

- **identity:** the agent's ERC-8004 registration on Base Sepolia. It names the operator, the Arkiv writers and the anchor contract to trust. Evidence from any other writer is ignored.
- **lane 0:** every batch is signed by a session key the operator delegated. The records chain by hash with no gaps from seq 0 to 7.
- **anchors:** a Merkle root covering seq 0…6 was anchored on Base Sepolia by an allowlisted recorder. Records up to that point can't be rewritten without the change showing.
- **unanchored:** records after the last anchor. They're still signed and chained, just not anchored yet, so this is info, not a warning. Here it's the `session_end` record written after the last anchor.
- **structural:** the record bodies are encrypted, so this run checked signatures, hashes, chain and anchors, but not the contents. A reader key the operator granted you (`--reader-key FILE.afrkey`) decrypts every record and checks it too ("full").

Public RPCs are used by default. Pass `--base-rpc URL` for Base and `--identity-rpc URL` for the registry if you have your own.

## Verify against a local copy

`fr mirror pull` saves every entity of the agent from Arkiv to one JSON-lines file. `--mirror` then verifies against that file instead of Arkiv, with the same checks and no access key. The chains are still read for identity and anchors. Editing the file changes nothing about what passes: the signatures, hash chain and anchors decide, so any tampering shows up.

```bash
fr mirror pull eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:10588 --out demo.jsonl
```
```bash
fr verify agent eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:10588 --mirror demo.jsonl
```

Flip one byte of a batch's `payload` in the file and run it again: the result is `FAIL` (exit 2), with a finding naming the lane and seq of the broken record or batch, such as `✖ FRAME_DECODE lane 0 seq 0`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `PASS` |
| 1 | `PASS_WITH_WARNINGS` (2 with `--strict`) |
| 2 | `FAIL`: a finding says what broke and where |
| 3 | usage or infrastructure error (RPC down, no access key) |

Add `--json` for the full report.

## Other commands

```bash
fr agent show <agentId>                         # the registration and its afr service entry
fr prove <agentId> <seq> --out proof.json       # one record with its batch, checkpoint and Merkle proof
fr keys reader new --out me.afrkey              # a reader key to send an operator for full verification
fr mirror pull <agentId> --out mirror.jsonl     # a local copy for verify --mirror
```

`fr --help` lists everything, including `fr journal verify` for a recorder's local journal.
