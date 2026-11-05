import { type ReactNode, useEffect, useState } from "react";
import { ApiError } from "../lib/api.js";
import {
  type DisplayStatus,
  SEVERITIES,
  SEVERITY_CLASS,
  type Severity,
  short,
} from "../lib/format.js";

/** The current time, refreshed so relative times ("5 min ago") stay current. */
export function useNow(everyMs = 30_000) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(t);
  }, [everyMs]);
  return now;
}

export function SeverityChips({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const present = SEVERITIES.filter((s) => counts[s]);
  if (!present.length) return <span className="text-slate-500">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((s) => (
        <span key={s} className={`rounded px-1.5 py-0.5 text-xs font-medium ${SEVERITY_CLASS[s]}`}>
          {counts[s]} {s}
        </span>
      ))}
    </span>
  );
}

const STATUS_CLASS: Record<DisplayStatus, string> = {
  active: "text-emerald-700 dark:text-emerald-400",
  paused: "text-amber-700 dark:text-amber-400",
  archived: "text-slate-500",
  silent: "text-red-600 dark:text-red-400",
};
export const StatusText = ({ status }: { status: DisplayStatus }) => (
  <span className={`font-medium ${STATUS_CLASS[status]}`}>{status}</span>
);

export const Hash = ({ value, n }: { value: string; n?: number }) => (
  <span className="font-mono" title={value}>
    {short(value, n)}
  </span>
);

export const Card = ({ label, children }: { label: string; children: ReactNode }) => (
  <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
    <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
    <div className="mt-1 text-lg">{children}</div>
  </div>
);

export const Loading = () => <p className="text-slate-500">Loading…</p>;

export const Problem = ({ error }: { error: unknown }) => (
  <p role="alert" className="text-red-600 dark:text-red-400">
    {error instanceof ApiError
      ? error.status === 404
        ? "Not found, or you don't have access."
        : `The API returned an error (${error.code}).`
      : "Couldn't reach the API."}
  </p>
);
