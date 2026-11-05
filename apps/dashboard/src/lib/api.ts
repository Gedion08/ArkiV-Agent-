// API access (L9 §3, L8 §2): same-origin, session cookie, CSRF header on mutations via @afr/client.
import { createAfrClient, type paths } from "@afr/client";

type Json<O> = O extends { responses: { 200: { content: { "application/json": infer J } } } }
  ? J
  : never;
export type Agent = Json<paths["/v1/agents/{id}"]["get"]>["agent"];
export type AgentListItem = Json<paths["/v1/orgs/{org}/agents"]["get"]>["agents"][number];
export type Lane = Json<paths["/v1/agents/{id}/lanes"]["get"]>["lanes"][number];
export type Alert = Json<paths["/v1/orgs/{org}/alerts"]["get"]>["alerts"][number];
export type Activity = Json<paths["/v1/agents/{id}/activity"]["get"]>;
export type Org = Json<paths["/v1/orgs"]["get"]>["orgs"][number];

const CSRF_COOKIE = "__Host-afr-csrf";

/** The CSRF token the SIWE login set (JS-readable by design, L8 §2). */
export function csrfFrom(cookie: string): string | undefined {
  for (const c of cookie.split(/;\s*/))
    if (c.startsWith(`${CSRF_COOKIE}=`)) return c.slice(CSRF_COOKIE.length + 1);
  return undefined;
}

export function api() {
  const csrf = csrfFrom(document.cookie);
  return createAfrClient(location.origin, csrf ? { csrf } : {});
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

/** Unwraps an openapi-fetch result: non-2xx → ApiError carrying the API's `{ code }`. */
export async function ok<T>(
  p: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await p;
  if (response.ok && data !== undefined) return data;
  const code = (error as { code?: unknown } | undefined)?.code;
  throw new ApiError(response.status, typeof code === "string" ? code : `HTTP_${response.status}`);
}

/** The org's agents with their summaries: the list page and the sidebar share this cache entry. */
export const agentsQuery = (org: string) => ({
  queryKey: ["agents", org],
  queryFn: () => ok(api().GET("/v1/orgs/{org}/agents", { params: { path: { org } } })),
});
export const lanesQuery = (id: string) => ({
  queryKey: ["lanes", id],
  queryFn: () => ok(api().GET("/v1/agents/{id}/lanes", { params: { path: { id } } })),
});
/** One agent's open alerts (the API caps a page at 500; the overview says "500+" then). */
export const OPEN_ALERTS_PAGE = 500;
export const openAlertsQuery = (org: string, agent: string) => ({
  queryKey: ["alerts", org, "open", agent],
  queryFn: () =>
    ok(
      api().GET("/v1/orgs/{org}/alerts", {
        params: { path: { org }, query: { status: "open", agent, limit: OPEN_ALERTS_PAGE } },
      }),
    ),
});
/** 48 hours, so the overview can compare the last 24 with the 24 before. */
export const activityQuery = (id: string) => ({
  queryKey: ["activity", id],
  queryFn: () =>
    ok(api().GET("/v1/agents/{id}/activity", { params: { path: { id }, query: { hours: 48 } } })),
});
