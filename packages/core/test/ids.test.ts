import { keccak256, stringToBytes } from "viem";
import { describe, expect, test } from "vitest";
import {
  agentKey,
  batchId,
  deriveLockAddress,
  EVIDENCE_LOCK_ADDRESS,
  epochIdFor,
  isLocalAgentId,
  parseAgentId,
} from "../src/index.js";
import { AGENT_ID } from "./fixtures/headers.js";

describe("agent ids", () => {
  test("parses eip155 ids", () => {
    expect(parseAgentId(AGENT_ID)).toEqual({
      chainId: 8453n,
      registry: "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
      tokenId: 42n,
    });
  });

  test.each([
    "eip155:08453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42",
    "eip155:8453:0x8004A169fb4a3325136eb29fa0ceb6d2e539a432:42",
    "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a43:42",
    "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:042",
    "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:",
    " eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42",
  ])("rejects %s", (id) => {
    expect(() => parseAgentId(id)).toThrow(expect.objectContaining({ code: "AGENT_ID_INVALID" }));
  });

  test("agent_key = keccak(utf8(agent_id)), also for local ids", () => {
    expect(agentKey(AGENT_ID)).toBe(keccak256(stringToBytes(AGENT_ID)));
    const local = "local:9b2f4e0a-1c3d-4e5f-8a6b-7c8d9e0f1a2b";
    expect(isLocalAgentId(local)).toBe(true);
    expect(agentKey(local)).toBe(keccak256(stringToBytes(local)));
    expect(() => agentKey("local:not-a-uuid")).toThrow();
  });

  test("batch_id is deterministic and seq-sensitive", () => {
    const k = agentKey(AGENT_ID);
    expect(batchId(k, 0, 0n)).toBe(batchId(k, 0, 0n));
    expect(batchId(k, 0, 0n)).not.toBe(batchId(k, 0, 1n));
  });
});

describe("epochs", () => {
  test("month * 16 + rotation since 2025-01 UTC", () => {
    expect(epochIdFor(new Date("2025-01-01T00:00:00Z"))).toBe(0);
    expect(epochIdFor(new Date("2026-11-15T00:00:00Z"))).toBe(22 * 16);
    expect(epochIdFor(new Date("2026-11-15T00:00:00Z"), 3)).toBe(22 * 16 + 3);
    expect(epochIdFor(new Date("2026-11-30T23:59:59Z"))).toBe(
      epochIdFor(new Date("2026-11-01T00:00:00Z")),
    );
  });

  test("rejects bad input", () => {
    expect(() => epochIdFor(new Date("2024-12-31T23:59:59Z"))).toThrow();
    expect(() => epochIdFor(new Date(), 16)).toThrow();
  });
});

test("evidence lock address", () => {
  expect(EVIDENCE_LOCK_ADDRESS).toBe(deriveLockAddress());
  expect(EVIDENCE_LOCK_ADDRESS).toBe(
    `0x${keccak256(stringToBytes("AFR_EVIDENCE_LOCK_V1")).slice(26)}`,
  );
  expect(EVIDENCE_LOCK_ADDRESS).toMatch(/^0x[0-9a-f]{40}$/);
});
