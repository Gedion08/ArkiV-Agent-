import type { Agent, Alert } from "./api.js";

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
