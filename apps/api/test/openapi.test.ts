// L8 §1 / P7: the committed packages/client/openapi.json matches the route schemas.
// Regenerate with AFR_UPDATE_OPENAPI=1 pnpm --filter @afr/api test, then pnpm --filter @afr/client generate.
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { openApiDocument } from "../src/index.js";

const PATH = new URL("../../../packages/client/openapi.json", import.meta.url);

describe("OpenAPI", () => {
  test("document is generated from the route schemas and committed", async () => {
    const doc = await openApiDocument();
    const json = `${JSON.stringify(doc, null, 2)}\n`;
    if (process.env.AFR_UPDATE_OPENAPI) writeFileSync(PATH, json);
    expect(readFileSync(PATH, "utf8")).toBe(json);
    const paths = Object.keys(doc.paths as object);
    expect(paths).toEqual(
      expect.arrayContaining([
        "/v1/orgs/{org}/members",
        "/v1/invitations/accept",
        "/v1/orgs/{org}/invitations/{id}",
        "/v1/agents/{id}/auditors/{userId}",
        "/v1/agents/{id}/watched-addresses",
        "/v1/agents/{id}/batches",
        "/v1/recorder/checkpoints",
        "/v1/orgs/{org}/alerts",
        "/v1/alerts/{id}/resolve",
        "/v1/orgs/{org}/channels/{id}",
        "/v1/channels/{id}/test",
      ]),
    );
  });
});
