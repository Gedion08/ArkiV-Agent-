import { expect, test } from "vitest";
import { Recorder } from "../src/recorder.js";
import { env, tmpConfig } from "../test/fixtures/setup.js";

// R5 (L2 §15, Arch §12.1): capture() → normalise, JCS, keccak, sign, encrypt, SQLite insert. p99 ≤ 5 ms,
// policy off, 2 KiB args. AFR_BENCH_R5_P99_MS overrides the budget. shortcut: absolute budget only, no
// 10 % regression baseline yet; add one once CI runner timings are stable.
test("R5 recorder hot path p99", async () => {
  const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
  const args = { message: "x".repeat(2048) };
  const times: number[] = [];
  for (let i = 0; i < 2_200; i++) {
    const t0 = performance.now();
    rec.capture({ type: "tool_call", tool: { server: "bench", name: "echo" }, body: { args } });
    if (i >= 200) times.push(performance.now() - t0); // skip warm-up
  }
  await rec.close();
  times.sort((a, b) => a - b);
  const p50 = times[Math.floor(times.length * 0.5)] ?? 0;
  const p99 = times[Math.floor(times.length * 0.99)] ?? 0;
  process.stderr.write(`R5 capture(): p50 ${p50.toFixed(3)} ms, p99 ${p99.toFixed(3)} ms\n`);
  expect(p99).toBeLessThanOrEqual(Number(process.env.AFR_BENCH_R5_P99_MS ?? 5));
}, 120_000);
