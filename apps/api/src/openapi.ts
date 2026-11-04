// L8 §1 contract-first: the OpenAPI 3.1 document generated from the route schemas. packages/client
// commits it (openapi.json) and generates its types from it; test/openapi.test.ts fails on drift.
import pg from "pg";
import { localKeyWrapper } from "./secrets.js";
import { buildServer } from "./server.js";

export async function openApiDocument(): Promise<Record<string, unknown>> {
  // the pool never connects: building the routes needs no database
  const pool = new pg.Pool({ max: 1 });
  const app = await buildServer({
    pool,
    siweDomain: "openapi.invalid",
    keys: localKeyWrapper(new Uint8Array(32)),
  });
  try {
    await app.ready();
    return app.swagger() as unknown as Record<string, unknown>;
  } finally {
    await app.close();
    await pool.end();
  }
}
