import { defineConfig, mergeConfig } from "vitest/config";
import { config } from "./vitest.config.ts";

// Hot-path benchmarks run alone (one file at a time) so parallel tests don't skew timings.
const bench = mergeConfig(config, defineConfig({ test: { fileParallelism: false } }));
bench.test.include = ["bench/**/*.bench.test.ts"]; // mergeConfig would append to the unit-test include
export default bench;
