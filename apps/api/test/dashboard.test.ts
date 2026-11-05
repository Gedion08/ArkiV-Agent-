// ADR-026: the API serves the dashboard build. No Postgres needed: these routes never query.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { dashboardCsp } from "../src/dashboard.js";
import { buildServer, localKeyWrapper } from "../src/index.js";

const CSP_META = `<meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;; script-src &#39;self&#39;">`;

describe("dashboard files", () => {
  const dir = mkdtempSync(join(tmpdir(), "afr-dash-"));
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    writeFileSync(
      join(dir, "index.html"),
      `<!doctype html><head>${CSP_META}</head><body>app</body>`,
    );
    mkdirSync(join(dir, "assets"));
    writeFileSync(join(dir, "assets", "index-abc.js"), "console.log(1)");
    writeFileSync(join(dir, "assets", "index-abc.js.map"), "{}");
    app = await buildServer({
      pool: new pg.Pool({ connectionString: "postgres://unused@127.0.0.1:1/x" }),
      siweDomain: "app.afr.test",
      keys: localKeyWrapper(new Uint8Array(32)),
      dashboardDir: dir,
    });
  });
  afterAll(async () => {
    await app?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("app routes get index.html with the CSP header (+ frame-ancestors) and no caching", async () => {
    for (const url of ["/", "/login", "/o/0b8f5f3e-4a51-4c0e-9d1e-2f1a9c8b7d6e/agents?x=1"]) {
      const r = await app.inject({ method: "GET", url });
      expect(r.statusCode).toBe(200);
      expect(r.body).toContain("<body>app</body>");
      expect(r.headers["content-type"]).toBe("text/html; charset=utf-8");
      expect(r.headers["content-security-policy"]).toBe(
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
      );
      expect(r.headers["cross-origin-opener-policy"]).toBe("same-origin-allow-popups");
      expect(r.headers["cache-control"]).toBe("no-cache");
    }
  });

  test("hashed assets are immutable; missing files, source maps and traversal are 404", async () => {
    const js = await app.inject({ method: "GET", url: "/assets/index-abc.js" });
    expect(js.statusCode).toBe(200);
    expect(js.headers["content-type"]).toBe("text/javascript; charset=utf-8");
    expect(js.headers["cache-control"]).toBe("public, max-age=31536000, immutable");
    for (const url of [
      "/assets/missing.js",
      "/assets/index-abc.js.map",
      "/favicon.ico",
      "/../package.json",
      "/assets/..%2F..%2Fpackage.json",
    ])
      expect((await app.inject({ method: "GET", url })).statusCode, url).toBe(404);
  });

  test("API paths are never answered with the app", async () => {
    const r = await app.inject({ method: "GET", url: "/v1/nope" });
    expect(r.statusCode).toBe(404);
    expect(r.body).not.toContain("<body>app</body>");
    const health = await app.inject({ method: "GET", url: "/healthz" });
    expect(health.body).not.toContain("<body>app</body>");
  });

  test("a build without a CSP meta is refused", () => {
    expect(() => dashboardCsp("<html></html>")).toThrow(/CSP/);
  });
});
