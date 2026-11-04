// Typed API client, generated from apps/api's OpenAPI document (L8 §1): `openapi.json` → `src/schema.ts`
// (`pnpm --filter @afr/client generate`). Dashboard calls send the session cookie; mutations need the CSRF token.
import createClient, { type ClientOptions } from "openapi-fetch";
import type { paths } from "./schema.js";

export const PACKAGE_NAME = "@afr/client";
export type { components, paths } from "./schema.js";

export interface AfrClientOptions extends Omit<ClientOptions, "baseUrl"> {
  /** `X-CSRF-Token` from the SIWE login (L8 §2), sent on non-GET requests. */
  csrf?: string;
}

export function createAfrClient(baseUrl: string, o: AfrClientOptions = {}) {
  const { csrf, ...rest } = o;
  const client = createClient<paths>({ baseUrl, credentials: "include", ...rest });
  if (csrf)
    client.use({
      onRequest: ({ request }) => {
        if (request.method !== "GET" && request.method !== "HEAD")
          request.headers.set("x-csrf-token", csrf);
        return request;
      },
    });
  return client;
}
