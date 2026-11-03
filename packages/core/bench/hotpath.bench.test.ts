import { expect, test } from "vitest";
import { buildHeader, hashHeader, localSigner, ZERO_HASH } from "../src/index.js";
import { SESSION_KEY_PK, toolCall } from "../test/fixtures/headers.js";

// T9: build + hash + sign ≤ 1 ms p99 for a ~2 KiB header. AFR_BENCH_P99_MS overrides on slow machines.
test("T9 hot path p99", () => {
  const signer = localSigner(SESSION_KEY_PK);
  const meta = Object.fromEntries(
    Array.from({ length: 16 }, (_, i) => [`key_${i}`, "v".repeat(100)]),
  );
  const input = { ...toolCall(), meta };
  const times: number[] = [];
  for (let i = 0; i < 2_200; i++) {
    const t0 = performance.now();
    const h = buildHeader(input, { seq: BigInt(i), prevHash: ZERO_HASH });
    signer.signDigest(hashHeader(h));
    if (i >= 200) times.push(performance.now() - t0); // skip warm-up
  }
  times.sort((a, b) => a - b);
  const p50 = times[Math.floor(times.length * 0.5)] ?? 0;
  const p99 = times[Math.floor(times.length * 0.99)] ?? 0;
  process.stderr.write(`T9 build+hash+sign: p50 ${p50.toFixed(3)} ms, p99 ${p99.toFixed(3)} ms\n`);
  expect(p99).toBeLessThanOrEqual(Number(process.env.AFR_BENCH_P99_MS ?? 1));
});
