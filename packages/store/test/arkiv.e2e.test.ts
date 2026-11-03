// P2-08: conformance on Rabdi (ARKIV_E2E=1). Spends test GLM: ≈ 30 small creates per run
// (c5Count 20), capped at 0.2 tGLM. Credentials come from the repo-root .env by name.
import { existsSync, readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { privateKeyToAccount } from "viem/accounts";
import { describe } from "vitest";
import { createArkivStore, MemoryWriteJournal } from "../src/index.js";
import { conformance } from "./conformance.js";

const ENV = new URL("../../../.env", import.meta.url);
// process.loadEnvFile segfaults inside vitest worker threads (Node 22.23); parse instead.
if (process.env.ARKIV_E2E === "1" && existsSync(ENV))
  for (const [k, v] of Object.entries(parseEnv(readFileSync(ENV, "utf8")))) process.env[k] ??= v;
const ready =
  process.env.ARKIV_E2E === "1" &&
  !!process.env.ARKIV_ACCESS_KEY &&
  !!process.env.AFR_ARKIV_WRITER_KEY;

const store = (key: string) =>
  createArkivStore({
    accessKey: process.env.ARKIV_ACCESS_KEY as string,
    writerKey: key,
    journal: new MemoryWriteJournal(),
    spendCapWei: 200_000_000_000_000_000n,
  });

describe.skipIf(!ready)("Arkiv (Rabdi)", () => {
  conformance("arkiv", async () => {
    const a = store(process.env.AFR_ARKIV_WRITER_KEY as string);
    const bKey = process.env.AFR_ARKIV_WRITER_KEY_B;
    return {
      a,
      ...(bKey ? { b: store(bKey) } : {}),
      writerA: privateKeyToAccount(process.env.AFR_ARKIV_WRITER_KEY as `0x${string}`).address,
      expiry: {
        expiresAt: { date: new Date(Date.now() + 60_000) },
        wait: () => new Promise((r) => setTimeout(r, 75_000)),
      },
      c5Count: 20,
    };
  });
});
