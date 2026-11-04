# ERC-8004 ABIs and addresses: sources

Fetched for P3-04 on 2026-11-04. ERC-8004 is a Draft and its names have changed between drafts, so
re-check these before relying on new functions. Everything ERC-8004-specific stays in this package.

## Sources

- Contracts repo: https://github.com/erc-8004/erc-8004-contracts, latest commit
  `b9e466c250744a7e06b13dff9d3c2844ed64f825` (2026-08-15, "Fixed typo").
  - `contracts/IdentityRegistryUpgradeable.sol` (`getVersion()` = "2.0.0"): `register` (3 overloads),
    `setAgentURI`, `getMetadata`/`setMetadata` (bytes values, `MetadataEntry {string metadataKey; bytes metadataValue}`),
    `getAgentWallet`/`setAgentWallet`/`unsetAgentWallet`, events `Registered`, `URIUpdated`, `MetadataSet`.
    `ownerOf`, `tokenURI` and `Transfer` are inherited from OpenZeppelin ERC-721 (URI storage).
  - `contracts/ValidationRegistryUpgradeable.sol` ("2.0.0"): `validationRequest`, `validationResponse`
    (`response` uint8 ≤ 100, `tag` string), `getValidationStatus`.
  - `ERC8004SPEC.md`: registration file (`type` = `https://eips.ethereum.org/EIPS/eip-8004#registration-v1`,
    `services` with `name`/`endpoint`/`version`, `registrations` with `agentId`/`agentRegistry`).
- Addresses: the repo README "Contract Addresses", matching https://docs.base.org/ai-agents/reference/contracts.

| Chain | IdentityRegistry | ReputationRegistry |
|---|---|---|
| Base Sepolia 84532 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | `0x8004B663056A597Dffe9eCcC1965A193B7388713` |
| Base 8453 | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |

No ValidationRegistry is listed for Base. The README says its spec is still being updated.

## Checked on-chain (Base Sepolia, 2026-11-04)

- IdentityRegistry is an ERC-1967 (UUPS) proxy, implementation `0x7274e874ca62410a93bd8bf61c69d8045e399c02`,
  `getVersion()` "2.0.0", `name()` "AgentIdentity", first code at block 36304145.
- Upgradeable means the owner can change behaviour: the adapter reads only `ownerOf`, `tokenURI` and
  `getAgentWallet`, and the verifier treats their answers as of the block it queried.
- The public RPC (`sepolia.base.org`) limits `eth_getLogs` to 200 blocks and prunes headers before
  block 46,500,000, so `operatorAt` uses historical `ownerOf` instead of a Transfer-log scan (L5 §4.3).
