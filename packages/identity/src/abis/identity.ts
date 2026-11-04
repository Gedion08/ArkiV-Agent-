// IdentityRegistry 2.0.0 (sources: ./README.md). ERC-721 parts are the OpenZeppelin signatures.
import { parseAbi } from "viem";

export const IDENTITY_REGISTRY_ABI = parseAbi([
  "struct MetadataEntry { string metadataKey; bytes metadataValue; }",
  "function register() returns (uint256 agentId)",
  "function register(string agentURI) returns (uint256 agentId)",
  "function register(string agentURI, MetadataEntry[] metadata) returns (uint256 agentId)",
  "function setAgentURI(uint256 agentId, string newURI)",
  "function getMetadata(uint256 agentId, string metadataKey) view returns (bytes)",
  "function getAgentWallet(uint256 agentId) view returns (address)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function transferFrom(address from, address to, uint256 tokenId)",
  "event Registered(uint256 indexed agentId, string agentURI, address indexed owner)",
  "event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)",
  "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)",
  "error ERC721NonexistentToken(uint256 tokenId)",
]);

/** Base: the README's IdentityRegistry deployments. */
export const ERC8004_IDENTITY_REGISTRY: Readonly<Record<number, `0x${string}`>> = {
  84532: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  8453: "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
};
