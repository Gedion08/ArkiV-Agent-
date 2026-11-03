import { expect, test } from "vitest";
import { createCanary, createLogger, memoryDestination, PACKAGE_NAME } from "../src/index.js";

test("package loads", () => {
  expect(PACKAGE_NAME).toBe("@afr/log");
});

test("redacts plaintext fields so a canary never reaches the log", () => {
  const canary = createCanary();
  const dest = memoryDestination();
  const log = createLogger({ name: "t", destination: dest });
  log.info({ body: canary.value, call: { args: { q: canary.value } }, seq: 1 }, "recorded");
  expect(dest.output()).toContain('"seq":1');
  canary.assertAbsent(dest.output());
});

test("canary detects a leak", () => {
  const canary = createCanary();
  expect(() => canary.assertAbsent(`x ${canary.value} y`)).toThrow("canary leaked");
});
