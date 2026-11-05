// Shared UI (L9 §6). Colours come from the tokens in index.css, so nothing here needs dark: variants.
import { AlertTriangle, ChevronRight, type LucideIcon } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { ApiError } from "../lib/api.js";
import {
  agentLabel,
  type DisplayStatus,
  SEVERITIES,
  SEVERITY_CLASS,
  type Severity,
  short,
} from "../lib/format.js";
import { Link } from "./link.js";

/** The current time, refreshed so relative times ("5 min ago") stay current. */
export function useNow(everyMs = 30_000) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(t);
  }, [everyMs]);
  return now;
}

const BTN =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-3.5 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50";
export const btn = {
  primary: `${BTN} bg-accent text-accent-fg hover:bg-accent-hover`,
  secondary: `${BTN} border border-line-strong bg-raised text-fg hover:bg-surface`,
  ghost: `${BTN} text-muted hover:bg-surface hover:text-fg`,
};

export const SeverityPill = ({
  severity,
  children,
}: {
  severity: Severity;
  children?: ReactNode;
}) => (
  <span
    className={`inline-flex h-5 items-center rounded-full px-2 text-xs font-medium whitespace-nowrap ${SEVERITY_CLASS[severity]}`}
  >
    {children ?? severity[0]?.toUpperCase() + severity.slice(1)}
  </span>
);

export function SeverityChips({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const present = SEVERITIES.filter((s) => counts[s]);
  if (!present.length) return <span className="text-muted">None</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((s) => (
        <SeverityPill key={s} severity={s}>
          {counts[s]} {s}
        </SeverityPill>
      ))}
    </span>
  );
}

const STATUS: Record<DisplayStatus, { label: string; pill: string; dot: string }> = {
  active: { label: "Active", pill: "bg-ok-soft text-ok-soft-fg", dot: "bg-ok" },
  paused: { label: "Paused", pill: "bg-warn-soft text-warn-soft-fg", dot: "bg-warn" },
  archived: { label: "Archived", pill: "bg-info-soft text-info-soft-fg", dot: "bg-muted" },
  silent: { label: "Silent", pill: "bg-bad-soft text-bad-soft-fg", dot: "bg-bad" },
};
export const StatusDot = ({ status }: { status: DisplayStatus }) => (
  <span aria-hidden className={`size-2 shrink-0 rounded-full ${STATUS[status].dot}`} />
);
export const StatusBadge = ({ status }: { status: DisplayStatus }) => (
  <span
    className={`inline-flex h-6 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium ${STATUS[status].pill}`}
  >
    <StatusDot status={status} />
    {STATUS[status].label}
  </span>
);

export const Hash = ({ value, n }: { value: string; n?: number }) => (
  <span className="font-mono" title={value}>
    {short(value, n)}
  </span>
);

/** An agent id as "#10593 Base Sepolia · registry 0x8004…8847", full id on hover. */
/** `compact`: in tables, the chain/registry part shows only on wide screens. */
export function AgentId({ id, compact = false }: { id: string; compact?: boolean }) {
  const { primary, secondary } = agentLabel(id);
  return (
    <span title={id}>
      <span className="font-mono font-medium text-fg">{primary}</span>
      {secondary && (
        <span className={`ml-1.5 text-muted ${compact ? "hidden xl:inline" : ""}`}>
          {secondary}
        </span>
      )}
    </span>
  );
}

export function PageHeader({
  crumbs,
  title,
  badge,
  meta,
  actions,
}: {
  crumbs: { label: string; href?: string }[];
  title: string;
  badge?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3">
      <nav aria-label="Breadcrumb">
        <ol className="flex flex-wrap items-center gap-1 text-sm text-muted">
          {crumbs.map((c, i) => (
            <li key={c.label} className="flex items-center gap-1">
              {i > 0 && <ChevronRight aria-hidden className="size-3.5" />}
              {c.href ? (
                <Link href={c.href} className="hover:text-fg">
                  {c.label}
                </Link>
              ) : (
                <span aria-current="page" className="text-fg">
                  {c.label}
                </span>
              )}
            </li>
          ))}
        </ol>
      </nav>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
            {badge}
          </div>
          {meta && (
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-muted">{meta}</div>
          )}
        </div>
        {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
      </div>
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className = "",
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`flex min-w-0 flex-col gap-4 rounded-xl border border-line bg-raised p-5 ${className}`}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-base font-semibold">{title}</h2>
        {description && <p className="text-[13px] text-muted">{description}</p>}
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export const Stat = ({
  label,
  value,
  sub,
  loading = false,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  loading?: boolean;
}) => (
  <div className="flex flex-col gap-1.5 rounded-xl border border-line bg-raised p-4">
    <span className="text-[13px] text-muted">{label}</span>
    {loading ? (
      <>
        <Skeleton className="h-8 w-24" />
        <Skeleton className="h-4 w-36" />
      </>
    ) : (
      <>
        <span className="text-[26px] leading-8 font-semibold tracking-tight tabular-nums">
          {value}
        </span>
        {sub && <span className="text-[13px] text-muted">{sub}</span>}
      </>
    )}
  </div>
);

export const Skeleton = ({ className = "" }: { className?: string }) => (
  <span aria-hidden className={`block animate-pulse rounded-md bg-line ${className}`} />
);

/** Placeholder rows shaped like the content they stand in for; screen readers hear "Loading". */
export const Loading = ({ rows = 3 }: { rows?: number }) => (
  <div className="flex flex-col gap-3">
    <span className="sr-only" role="status">
      Loading
    </span>
    {Array.from({ length: rows }, (_, i) => (
      // biome-ignore lint/suspicious/noArrayIndexKey: static placeholders
      <Skeleton key={i} className="h-10 w-full" />
    ))}
  </div>
);

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-line-strong px-6 py-12 text-center">
      <span className="flex size-10 items-center justify-center rounded-full bg-accent-soft text-accent-soft-fg">
        <Icon aria-hidden className="size-5" />
      </span>
      <h2 className="text-base font-semibold">{title}</h2>
      <div className="max-w-md text-muted">{children}</div>
    </div>
  );
}

export const Problem = ({ error }: { error: unknown }) => (
  <div
    role="alert"
    className="flex items-start gap-3 rounded-xl border border-bad-soft bg-bad-soft px-4 py-3 text-bad-soft-fg"
  >
    <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0" />
    <p>
      {error instanceof ApiError
        ? error.status === 404
          ? "Not found, or you don't have access."
          : `The API returned an error (${error.code}).`
        : "Couldn't reach the API. Check your connection and reload."}
    </p>
  </div>
);
