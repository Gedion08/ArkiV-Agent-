// L11 §2 API container: env validation before any connection, /healthz for the ALB (no DB, no rate limit,
// not in the OpenAPI contract), and a real start (migrate → listen) when AFR_PG_URL is set.
import { randomBytes } from "node:crypto";
import pg from "pg";
import { describe, expect, test } from "vitest";
import { buildServer, localKeyWrapper, openApiDocument } from "../src/index.js";
import { readApiEnv, startApi } from "../src/main.js";

const URL = process.env.AFR_PG_URL;
const KEK = "ab".repeat(32);
const BASE = { AFR_PG_URL: "postgres://x@127.0.0.1:1/x", AFR_SIWE_DOMAIN: "app.afr.test" };

describe("readApiEnv", () => {
  test("defaults, and every misconfiguration is CONFIG before anything connects", () => {
    expect(readApiEnv({ ...BASE, AFR_API_LOCAL_KEK: KEK })).toMatchObject({
      port: 8080,
      host: "0.0.0.0",
      siweDomain: "app.afr.test",
    });
    expect(readApiEnv({ ...BASE, AFR_KMS_ENVELOPE_KEY_ID: "arn:aws:kms:…" }).kmsKey).toBe(
      "arn:aws:kms:…",
    );
    for (const env of [
      { AFR_SIWE_DOMAIN: "d", AFR_API_LOCAL_KEK: KEK },
      { AFR_PG_URL: "postgres://x", AFR_API_LOCAL_KEK: KEK },
      { ...BASE },
      { ...BASE, AFR_API_LOCAL_KEK: "AB".repeat(32) },
      { ...BASE, AFR_API_LOCAL_KEK: KEK, AFR_DASHBOARD_ORIGIN: "http://app.example" },
      { ...BASE, AFR_API_LOCAL_KEK: KEK, AFR_DASHBOARD_ORIGIN: "https://app.example/path" },
      { ...BASE, AFR_API_LOCAL_KEK: KEK, AFR_SMTP_URL: "smtp://h:25" },
      { ...BASE, AFR_API_LOCAL_KEK: KEK, AFR_SIWE_RPC_URL: "https://r", AFR_SIWE_CHAIN_ID: "1" },
      { ...BASE, AFR_API_LOCAL_KEK: KEK, PORT: "http" },
    ])
      expect(() => readApiEnv(env)).toThrow(expect.objectContaining({ code: "CONFIG" }));
  });
});

describe("/healthz", () => {
  test("200 without touching the DB, never rate-limited, hidden from OpenAPI", async () => {
    // a pool to nowhere: any query would fail
    const pool = new pg.Pool({ connectionString: BASE.AFR_PG_URL, connectionTimeoutMillis: 200 });
    const app = await buildServer({
      pool,
      siweDomain: "app.afr.test",
      keys: localKeyWrapper(randomBytes(32)),
    });
    for (let i = 0; i < 30; i++) {
      const r = await app.inject({ method: "GET", url: "/healthz" });
      expect([r.statusCode, r.json()]).toEqual([200, { status: "ok" }]);
    }
    await app.close();
    await pool.end();
    expect(Object.keys((await openApiDocument()).paths as object)).not.toContain("/healthz");
  });
});

describe.skipIf(!URL)("startApi", () => {
  test("migrates, listens, serves /healthz and DB routes, closes cleanly", async () => {
    const schema = `afr_main_${randomBytes(4).toString("hex")}`;
    const admin = new pg.Pool({ connectionString: URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    try {
      const u = new globalThis.URL(URL as string);
      u.searchParams.set("options", `-c search_path=${schema}`);
      const api = await startApi({
        AFR_PG_URL: u.toString(),
        AFR_SIWE_DOMAIN: "app.afr.test",
        AFR_API_LOCAL_KEK: KEK,
        PORT: "0",
        HOST: "127.0.0.1",
      });
      try {
        expect(await (await fetch(`${api.url}/healthz`)).json()).toEqual({ status: "ok" });
        const nonce = await fetch(`${api.url}/v1/auth/nonce`);
        expect(nonce.status).toBe(200); // writes siwe_nonces: the migrations ran in this schema
        const { rows } = await admin.query(
          "SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = $1",
          [schema],
        );
        expect(rows[0].n).toBeGreaterThan(5);
      } finally {
        await api.close();
      }
    } finally {
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  });

  test("an unreachable database fails the start (the task exits; ECS restarts it)", async () => {
    await expect(
      startApi({ ...BASE, AFR_API_LOCAL_KEK: KEK, PORT: "0", HOST: "127.0.0.1" }),
    ).rejects.toThrow();
  });
});
