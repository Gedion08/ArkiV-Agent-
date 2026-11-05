// ADR-026: the API serves the dashboard's static build, so the SPA shares the API's origin (the session cookie
// is __Host- and SameSite=Strict, L8 §2). Files are loaded into memory once; requests never touch the disk.
// App routes get index.html; /v1/* and unknown files stay 404.
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import { AfrError } from "@afr/core";
import type { FastifyInstance } from "fastify";

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".woff2": "font/woff2",
  ".wasm": "application/wasm",
  ".txt": "text/plain; charset=utf-8",
};

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else if (e.isFile() && !e.name.endsWith(".map")) out.push(p);
  }
  return out;
}

/** The build's <meta> CSP as a header, plus frame-ancestors, which a <meta> can't carry (L9 §5). */
export function dashboardCsp(indexHtml: string): string {
  const m = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(indexHtml);
  if (!m) throw new AfrError("CONFIG", "dashboard index.html has no CSP meta");
  return `${(m[1] as string).replaceAll("&#39;", "'")}; frame-ancestors 'none'`;
}

export async function dashboardRoutes(app: FastifyInstance, dir: string): Promise<void> {
  const files = new Map<string, { body: Buffer; type: string }>();
  for (const f of await walk(dir))
    files.set(`/${relative(dir, f).split(sep).join("/")}`, {
      body: await readFile(f),
      type: TYPES[extname(f)] ?? "application/octet-stream",
    });
  const index = files.get("/index.html");
  if (!index) throw new AfrError("CONFIG", "AFR_DASHBOARD_DIR has no index.html");
  const csp = dashboardCsp(index.body.toString("utf8"));

  // in-memory files: exempt from the per-session API limit, which a page load's chunks would trip
  app.get("/*", { config: { rateLimit: false } }, (req, reply) => {
    const path = req.url.split("?")[0] as string;
    if (path.startsWith("/v1/")) return reply.callNotFound();
    // a path with a file extension is a file; anything else is an app route
    const f = files.get(path) ?? (extname(path) ? undefined : index);
    if (!f) return reply.callNotFound();
    return (
      reply
        .type(f.type)
        .header("content-security-policy", csp)
        // the Coinbase Wallet popup talks back to its opener
        .header("cross-origin-opener-policy", "same-origin-allow-popups")
        .header(
          "cache-control",
          path.startsWith("/assets/") ? "public, max-age=31536000, immutable" : "no-cache",
        )
        .send(f.body)
    );
  });
}
