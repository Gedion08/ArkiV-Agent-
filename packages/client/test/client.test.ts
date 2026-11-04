// L8 P7: the client's types are generated from the committed OpenAPI document (no drift) and type calls.
import { readFileSync } from "node:fs";
import openapiTS, { astToString } from "openapi-typescript";
import { expect, expectTypeOf, test } from "vitest";
import { createAfrClient } from "../src/index.js";

test("src/schema.ts is what openapi-typescript generates from openapi.json", async () => {
  const doc = new URL("../openapi.json", import.meta.url);
  const generated = astToString(await openapiTS(doc));
  const committed = readFileSync(new URL("../src/schema.ts", import.meta.url), "utf8");
  // the CLI adds a banner; compare the type bodies
  expect(committed.slice(committed.indexOf("export interface paths"))).toBe(
    generated.slice(generated.indexOf("export interface paths")),
  );
});

test("typed calls; CSRF token on mutations only", async () => {
  const seen: Request[] = [];
  const fetch = async (req: Request) => {
    seen.push(req);
    return Response.json(
      req.method === "GET" ? { batches: [], next_from_seq: null } : { ok: true },
    );
  };
  const api = createAfrClient("https://api.afr.test", { csrf: "c5rf", fetch });
  const id = "00000000-0000-4000-8000-000000000000";
  const { data } = await api.GET("/v1/agents/{id}/batches", {
    params: { path: { id }, query: { lane: 0, limit: 10 } },
  });
  expectTypeOf(data?.next_from_seq).toEqualTypeOf<string | null | undefined>();
  await api.POST("/v1/auth/logout");
  expect(seen.map((r) => [r.method, r.headers.get("x-csrf-token")])).toEqual([
    ["GET", null],
    ["POST", "c5rf"],
  ]);
  expect(new URL(seen[0]?.url as string).search).toBe("?lane=0&limit=10");
});
