// L9 §1 routes built so far, on the History API (three routes don't need a router dependency).
import { useSyncExternalStore } from "react";

export type Route =
  | { name: "home" }
  | { name: "login" }
  | { name: "agents"; org: string }
  | { name: "agent"; org: string; id: string }
  | { name: "not_found" };

const ID = "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
const AGENTS = new RegExp(`^/o/${ID}/agents/?$`);
const AGENT = new RegExp(`^/o/${ID}/agents/${ID}/?$`);

export function parseRoute(path: string): Route {
  if (path === "/") return { name: "home" };
  if (path === "/login") return { name: "login" };
  const a = AGENTS.exec(path);
  if (a) return { name: "agents", org: a[1] as string };
  const b = AGENT.exec(path);
  if (b) return { name: "agent", org: b[1] as string, id: b[2] as string };
  return { name: "not_found" };
}

export const hrefs = {
  agents: (org: string) => `/o/${org}/agents`,
  agent: (org: string, id: string) => `/o/${org}/agents/${id}`,
};

export function navigate(to: string, replace = false) {
  if (replace) history.replaceState(null, "", to);
  else history.pushState(null, "", to);
  dispatchEvent(new PopStateEvent("popstate"));
}

const subscribe = (cb: () => void) => {
  addEventListener("popstate", cb);
  return () => removeEventListener("popstate", cb);
};
export const usePath = () => useSyncExternalStore(subscribe, () => location.pathname);
