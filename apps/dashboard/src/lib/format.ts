import type { Agent, Alert, Lane } from "./api.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
/** L9 §6 severity colours; every chip also carries the severity as text. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-sky-500 text-white",
  info: "bg-slate-400 text-black",
};

/** 0x1234ab…cdef90, with the full value left for the title attribute. */
export const short = (h: string, n = 6) =>
  h.length <= 2 * n + 4 ? h : `${h.slice(0, n + 2)}…${h.slice(-n)}`;

export function ago(iso: string | null, now: number): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

export function severityCounts(alerts: Alert[], agentId: string) {
  const c: Partial<Record<Severity, number>> = {};
  for (const a of alerts) if (a.agent_id === agentId) c[a.severity] = (c[a.severity] ?? 0) + 1;
  return c;
}

export type DisplayStatus = Agent["status"] | "silent";
/** "silent" comes from the watcher's open RECORDER_SILENT alert (L6 §5), so list and inbox agree. */
export const displayStatus = (agent: Agent, open: Alert[]): DisplayStatus =>
  agent.status === "active" &&
  open.some((a) => a.agent_id === agent.id && a.type === "RECORDER_SILENT")
    ? "silent"
    : agent.status;

/** Latest batch across lanes (ISO strings from toISOString compare in time order). */
export const lastAction = (lanes: Lane[]) =>
  lanes.reduce<string | null>(
    (m, l) => (l.last_batch_at && (!m || l.last_batch_at > m) ? l.last_batch_at : m),
    null,
  );
