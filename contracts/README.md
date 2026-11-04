# contracts

`RecorderAnchor` (L5 §2): anchors AFR checkpoint roots. Immutable, holds no funds.

```bash
forge test --root contracts
```

## Deploy

`script/Deploy.s.sol` deploys through the canonical CREATE2 deployer (`0x4e59…956C`) with the salt
`keccak256("afr/RecorderAnchor/v1")`. The address depends only on the bytecode, the admin and the recorders:
the same three give the same address on every chain. Re-running finds the contract and sends nothing.

Env (put it in the repo's `.env`, never commit it):

| Variable | |
|---|---|
| `AFR_DEPLOYER_KEY` | pays gas, gets no role; a key used only for deploying |
| `AFR_ANCHOR_ADMIN` | edits the recorder allowlist only (a Safe in production) |
| `AFR_ANCHOR_RECORDERS` | comma-separated anchor-service signer addresses |
| `BASE_SEPOLIA_RPC_URL` | e.g. `https://sepolia.base.org` |
| `ETHERSCAN_API_KEY` | Etherscan v2 key (covers BaseScan) for `--verify` |

```bash
cd contracts && set -a && . ../.env && set +a && forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify
```

Then add `{address, fromBlock, version}` to `packages/core/src/anchors.ts`.
