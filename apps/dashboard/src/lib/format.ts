import type { Activity, Agent, Alert } from "./api.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
/** L9 §6 severity colours (design tokens); every pill also carries the severity as text. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-bad-soft text-bad-soft-fg",
  high: "bg-high-soft text-high-soft-fg",
  medium: "bg-warn-soft text-warn-soft-fg",
  low: "bg-low-soft text-low-soft-fg",
  info: "bg-info-soft text-info-soft-fg",
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

export function severityCounts(alerts: Alert[]) {
  const c: Partial<Record<Severity, number>> = {};
  for (const a of alerts) c[a.severity] = (c[a.severity] ?? 0) + 1;
  return c;
}

export type DisplayStatus = Agent["status"] | "silent";
/** "silent" comes from the watcher's open RECORDER_SILENT alert (L6 §5), so list and inbox agree. */
export const displayStatus = (status: Agent["status"], recorderSilent: boolean): DisplayStatus =>
  status === "active" && recorderSilent ? "silent" : status;

const CHAINS: Record<string, string> = {
  "1": "Ethereum",
  "8453": "Base",
  "84532": "Base Sepolia",
  "11155111": "Sepolia",
};
const EIP155 = /^eip155:(\d+):(0x[0-9a-f]{40}):(\d+)$/;
/**
 * ERC-8004 ids read as their token and chain ("#10593", "Base Sepolia · registry 0x8004…8847");
 * dev ids (`local:<uuid>`) as "local" and the uuid's first group.
 */
export function agentLabel(id: string): { primary: string; secondary: string } {
  const m = EIP155.exec(id);
  if (m)
    return {
      primary: `#${m[3]}`,
      secondary: `${CHAINS[m[1] as string] ?? `chain ${m[1]}`} · registry ${short(m[2] as string, 4)}`,
    };
  if (id.startsWith("local:")) return { primary: "local", secondary: id.slice(6, 14) };
  return { primary: id.length > 24 ? `${id.slice(0, 24)}…` : id, secondary: "" };
}

/**
 * The activity chart's last `n` hours plus totals: this window, the one before it (when the API returned
 * 2n hours) and the change in percent (null when there's nothing to compare with).
 */
export function activityWindow(hours: Activity["hours"], n = 24) {
  const shown = hours.slice(-n);
  const before = hours.slice(-2 * n, -n);
  const total = shown.reduce((s, h) => s + h.actions, 0);
  const prev = before.length === n ? before.reduce((s, h) => s + h.actions, 0) : null;
  return {
    shown,
    total,
    unlogged: shown.reduce((s, h) => s + h.unlogged, 0),
    peak: Math.max(0, ...shown.map((h) => h.actions)),
    changePct: prev ? Math.round(((total - prev) / prev) * 100) : null,
  };
}

/** 1284 → "1,284" (fixed locale, so screenshots and tests agree). */
export const count = (n: number) => n.toLocaleString("en-US");
