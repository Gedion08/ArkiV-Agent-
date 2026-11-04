// P2-06: conformance on PostgresStore. Needs a database: AFR_PG_URL=postgres://… (pnpm local:up
// provides one on :5432); skipped without it.
import pg from "pg";
import type { Hex } from "viem";
import { afterAll, describe, expect, test } from "vitest";
import { migratePostgres, PostgresStore } from "../src/index.js";
import { batchReq, conformance } from "./conformance.js";

const URL = process.env.AFR_PG_URL;
const A = "0x00000000000000000000000000000000000000aa" as Hex;
const B = "0x00000000000000000000000000000000000000bb" as Hex;

describe.skipIf(!URL)("postgres", () => {
  const pool = new pg.Pool({ connectionString: URL, max: 4 });
  afterAll(() => pool.end());

  conformance("postgres", async () => {
    await migratePostgres(pool);
    const clock = { now: Date.now() };
    const now = () => clock.now;
    return {
      a: new PostgresStore({ pool, writer: A, now }),
      b: new PostgresStore({ pool, writer: B, now }),
      writerA: A,
      expiry: {
        expiresAt: { days: 1 },
        wait: async () => {
          clock.now += 86_400_001;
        },
      },
    };
  });

  test("postgres: the guard trigger refuses direct UPDATE of readonly rows and DELETE of locked rows", async () => {
    await migratePostgres(pool);
    const s = new PostgresStore({ pool, writer: A });
    const locked = await s.await(await s.put(batchReq()));
    const codeOf = (p: Promise<unknown>) =>
      p.then(
        () => "NO_ERROR",
        (e: Error) => e.message,
      );
    const k = Buffer.from(locked.key.slice(2), "hex");
    expect(
      await codeOf(
        pool.query("UPDATE evidence_entities SET payload = '\\x00' WHERE key = $1", [k]),
      ),
    ).toMatch(/^READONLY/);
    expect(await codeOf(pool.query("DELETE FROM evidence_entities WHERE key = $1", [k]))).toMatch(
      /^NOT_OWNER/,
    );
    // bigints round-trip exactly beyond 2^53
    const big = batchReq({ attrs: { seq_from: 2n ** 63n - 1n } });
    const e = await s.get((await s.await(await s.put(big))).key, "afr.batch.v1");
    expect(e?.attrs.seq_from).toBe(2n ** 63n - 1n);
  });
});
