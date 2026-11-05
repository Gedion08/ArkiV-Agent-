// L9 §4.1 agent list. Last anchor and the verify badge come with P4-14.
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "../components/link.js";
import { AgentId, Loading, Problem, SeverityChips, StatusText, useNow } from "../components/ui.js";
import { api, ok } from "../lib/api.js";
import { ago, type DisplayStatus, displayStatus } from "../lib/format.js";
import { hrefs } from "../lib/route.js";

const STATUSES: DisplayStatus[] = ["active", "silent", "paused", "archived"];

export function AgentsPage({ org }: { org: string }) {
  const now = useNow();
  const agents = useQuery({
    queryKey: ["agents", org],
    queryFn: () => ok(api().GET("/v1/orgs/{org}/agents", { params: { path: { org } } })),
  });
  const list = agents.data?.agents ?? [];
  const [status, setStatus] = useState<DisplayStatus | "">("");
  const [critical, setCritical] = useState(false);

  if (agents.isPending) return <Loading />;
  if (agents.isError) return <Problem error={agents.error} />;
  // one request: the list carries each agent's lane and open-alert summary (L8 §4.3)
  const rows = list
    .map((a) => ({
      a,
      status: displayStatus(a.status, a.summary.recorder_silent),
      counts: a.summary.open_alerts,
      last: a.summary.last_batch_at,
    }))
    .filter((r) => (!status || r.status === status) && (!critical || r.counts.critical));

  return (
    <section>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Agents</h1>
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <label className="flex items-center gap-2">
            Status
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as DisplayStatus | "")}
              className="rounded border border-slate-300 bg-transparent px-2 py-1 dark:border-slate-600"
            >
              <option value="">all</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={critical}
              onChange={(e) => setCritical(e.target.checked)}
            />
            Has critical alerts
          </label>
        </div>
      </div>
      {list.length === 0 ? (
        <p className="mt-8 text-slate-600 dark:text-slate-400">
          No agents yet. Register one with{" "}
          <code className="font-mono">POST /v1/orgs/{"{org}"}/agents</code>, then point it at{" "}
          <code className="font-mono">fr-proxy</code>.
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-700">
              <tr>
                <th className="py-2 pr-4 font-medium">Name</th>
                <th className="py-2 pr-4 font-medium">Agent ID</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Last action</th>
                <th className="py-2 pr-4 font-medium">Open alerts</th>
                <th className="hidden py-2 pr-4 font-medium md:table-cell">Privacy</th>
                <th className="hidden py-2 font-medium md:table-cell">Retention</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ a, status: s, counts, last }) => (
                <tr key={a.id} className="border-b border-slate-100 dark:border-slate-800">
                  <td className="py-2 pr-4">
                    <Link
                      href={hrefs.agent(org, a.id)}
                      className="font-medium underline-offset-2 hover:underline"
                    >
                      {a.name}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">
                    <AgentId id={a.agent_id} compact />
                  </td>
                  <td className="py-2 pr-4">
                    <StatusText status={s} />
                  </td>
                  <td className="py-2 pr-4" title={last ?? undefined}>
                    {ago(last, now)}
                  </td>
                  <td className="py-2 pr-4">
                    <SeverityChips counts={counts} />
                  </td>
                  <td className="hidden py-2 pr-4 md:table-cell">{a.privacy_level}</td>
                  <td className="hidden py-2 md:table-cell">{a.retention_days} d</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <p className="mt-4 text-slate-500">No agents match the filters.</p>}
        </div>
      )}
    </section>
  );
}
