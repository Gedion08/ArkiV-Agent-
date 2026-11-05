// L9 §4.1 agent list. Last anchor and the verify badge come with P4-14.
import { useQuery } from "@tanstack/react-query";
import { Bot, SearchX } from "lucide-react";
import { useState } from "react";
import { Link } from "../components/link.js";
import {
  AgentId,
  EmptyState,
  Loading,
  PageHeader,
  Problem,
  SeverityChips,
  StatusBadge,
  useNow,
} from "../components/ui.js";
import { agentsQuery, api, ok } from "../lib/api.js";
import { ago, type DisplayStatus, displayStatus } from "../lib/format.js";
import { hrefs } from "../lib/route.js";

const FILTERS: { value: DisplayStatus | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "active", label: "Active" },
  { value: "silent", label: "Silent" },
  { value: "paused", label: "Paused" },
  { value: "archived", label: "Archived" },
];

export function AgentsPage({ org }: { org: string }) {
  const now = useNow();
  const agents = useQuery(agentsQuery(org));
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => ok(api().GET("/v1/orgs")) });
  const orgName = orgs.data?.orgs.find((o) => o.id === org)?.name ?? "Organisation";
  const [status, setStatus] = useState<DisplayStatus | "">("");
  const [critical, setCritical] = useState(false);

  const list = agents.data?.agents ?? [];
  // one request: the list carries each agent's lane and open-alert summary (L8 §4.3)
  const all = list.map((a) => ({
    a,
    status: displayStatus(a.status, a.summary.recorder_silent),
    counts: a.summary.open_alerts,
    last: a.summary.last_batch_at,
  }));
  const attention = all.filter((r) => r.status === "silent" || r.counts.critical).length;
  const rows = all.filter(
    (r) => (!status || r.status === status) && (!critical || r.counts.critical),
  );

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        crumbs={[{ label: orgName }, { label: "Agents" }]}
        title="Agents"
        meta={
          agents.isSuccess && (
            <span>
              {list.length} {list.length === 1 ? "agent" : "agents"}
              {attention > 0 && (
                <span className="text-bad-soft-fg"> · {attention} need attention</span>
              )}
            </span>
          )
        }
      />

      {agents.isPending ? (
        <Loading rows={4} />
      ) : agents.isError ? (
        <Problem error={agents.error} />
      ) : list.length === 0 ? (
        <EmptyState icon={Bot} title="No agents yet">
          <p>
            Register an agent with{" "}
            <code className="rounded bg-surface px-1 font-mono text-[13px] text-fg">
              POST /v1/orgs/{"{org}"}/agents
            </code>
            , then point it at{" "}
            <code className="rounded bg-surface px-1 font-mono text-[13px] text-fg">fr-proxy</code>.
            Its actions show up here as they're recorded.
          </p>
        </EmptyState>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <fieldset className="flex flex-wrap rounded-lg border border-line-strong bg-surface p-0.5">
              <legend className="sr-only">Status</legend>
              {FILTERS.map((f) => (
                <button
                  key={f.label}
                  type="button"
                  aria-pressed={status === f.value}
                  onClick={() => setStatus(f.value)}
                  className={`min-h-8 rounded-md px-3 text-[13px] font-medium ${
                    status === f.value
                      ? "bg-raised text-fg shadow-[0_0_0_1px_var(--color-line-strong)]"
                      : "text-muted hover:text-fg"
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </fieldset>
            <label className="flex min-h-9 cursor-pointer items-center gap-2 rounded-lg px-2 text-[13px] text-fg-2">
              <input
                type="checkbox"
                checked={critical}
                onChange={(e) => setCritical(e.target.checked)}
                className="size-4 accent-[var(--color-accent)]"
              />
              Has critical alerts
            </label>
          </div>

          {rows.length === 0 ? (
            <EmptyState icon={SearchX} title="No agents match these filters">
              <button
                type="button"
                className="text-accent hover:underline"
                onClick={() => {
                  setStatus("");
                  setCritical(false);
                }}
              >
                Clear filters
              </button>
            </EmptyState>
          ) : (
            <>
              {/* phones: one card per agent instead of a table that scrolls sideways */}
              <ul className="flex flex-col divide-y divide-line rounded-xl border border-line bg-raised sm:hidden">
                {rows.map(({ a, status: s, counts, last }) => (
                  <li key={a.id}>
                    <Link
                      href={hrefs.agent(org, a.id)}
                      className="flex flex-col gap-2 px-4 py-3.5 hover:bg-surface"
                    >
                      <span className="flex items-center gap-2">
                        <span className="truncate font-medium text-fg">{a.name}</span>
                        <span className="ml-auto">
                          <StatusBadge status={s} />
                        </span>
                      </span>
                      <span className="flex items-center gap-3 text-[13px] text-muted">
                        <AgentId id={a.agent_id} compact />
                        <span title={last ?? undefined}>{ago(last, now)}</span>
                      </span>
                      <SeverityChips counts={counts} />
                    </Link>
                  </li>
                ))}
              </ul>
              <div className="hidden overflow-x-auto rounded-xl border border-line bg-raised sm:block">
                <table className="w-full text-left text-[13px]">
                  <thead className="border-b border-line text-muted">
                    <tr>
                      <th className="px-4 py-3 font-medium">Name</th>
                      <th className="px-4 py-3 font-medium whitespace-nowrap">Agent ID</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium whitespace-nowrap">Last action</th>
                      <th className="px-4 py-3 font-medium whitespace-nowrap">Open alerts</th>
                      <th className="hidden px-4 py-3 font-medium md:table-cell">Privacy</th>
                      <th className="hidden px-4 py-3 font-medium lg:table-cell">Retention</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {rows.map(({ a, status: s, counts, last }) => (
                      <tr key={a.id} className="hover:bg-surface">
                        <td className="px-4 py-3">
                          <Link
                            href={hrefs.agent(org, a.id)}
                            className="font-medium whitespace-nowrap text-fg hover:text-accent hover:underline"
                          >
                            {a.name}
                          </Link>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <AgentId id={a.agent_id} compact />
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge status={s} />
                        </td>
                        <td
                          className="px-4 py-3 whitespace-nowrap text-fg-2"
                          title={last ?? undefined}
                        >
                          {ago(last, now)}
                        </td>
                        <td className="px-4 py-3">
                          <SeverityChips counts={counts} />
                        </td>
                        <td className="hidden px-4 py-3 text-fg-2 md:table-cell">
                          Level {a.privacy_level}
                        </td>
                        <td className="hidden px-4 py-3 whitespace-nowrap text-fg-2 lg:table-cell">
                          {a.retention_days} days
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
