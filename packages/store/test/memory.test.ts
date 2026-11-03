// P2-05: conformance on MemoryStore + memory-only checks (failure injection, lifetime cap).
import type { Hex } from "viem";
import { expect, test } from "vitest";
import { MemoryChain, MemoryStore } from "../src/index.js";
import { batchReq, conformance } from "./conformance.js";

const A = "0x00000000000000000000000000000000000000aa" as Hex;
const B = "0x00000000000000000000000000000000000000bb" as Hex;

conformance("memory", async () => {
  const chain = new MemoryChain();
  const a = new MemoryStore(chain, A, 0);
  return {
    a,
    b: new MemoryStore(chain, B, 0),
    writerA: A,
    expiry: { expiresAt: { days: 1 }, wait: async () => chain.advance(43_201n) },
    failNext: (k) => a.failNext(k),
  };
});

const codeOf = (p: Promise<unknown>) =>
  p.then(
    () => "NO_ERROR",
    (e: { code?: string }) => e.code,
  );

test("memory: lifetime capped at MAX_LIFETIME like Arkiv; 429/timeout injection; close", async () => {
  const s = new MemoryStore(new MemoryChain(), A);
  expect(await codeOf(s.put(batchReq({ expiresAt: { days: 183 } })))).toBe("EXPIRY_INVALID");
  expect(await codeOf(s.put(batchReq({ expiresAt: { days: 182 } })))).toBe("NO_ERROR");
  s.failNext("429");
  const r = batchReq();
  expect(await codeOf(s.put(r))).toBe("RATE_LIMITED");
  expect((await s.reconcile({ store: "memory", idempotencyKey: r.idempotencyKey })).state).toBe(
    "not_sent",
  );
  s.failNext("timeout");
  const w = await s.put(batchReq());
  expect(await codeOf(s.await(w))).toBe("TIMEOUT");
  expect((await s.reconcile(w)).state).toBe("confirmed");
  await s.await(w); // injected failure fires once
  const dup = batchReq();
  await s.put(dup);
  expect(await codeOf(s.put({ ...dup, payload: new Uint8Array([9]) }))).toBe(
    "IDEMPOTENCY_CONFLICT",
  );
  await s.close();
  expect(await codeOf(s.head())).toBe("CLOSED");
});
