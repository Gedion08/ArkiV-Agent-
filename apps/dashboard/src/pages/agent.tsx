// L9 §4.2 agent overview from API data. The decrypted cards (actions, value moved), the mini timeline and
// the verify badge need the reader key and workers (P4-09 … P4-14).
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "../components/link.js";
import {
  AgentId,
  Card,
  Hash,
  Loading,
  Pending,
  Problem,
  SeverityChips,
  StatusText,
  useNow,
} from "../components/ui.js";
import { api, lanesQuery, OPEN_ALERTS_PAGE, ok, openAlertsQuery } from "../lib/api.js";
import { ago, displayStatus, SEVERITY_CLASS, severityCounts } from "../lib/format.js";
import { hrefs } from "../lib/route.js";

export function AgentPage({ org, id }: { org: string; id: string }) {
  const now = useNow();
  const agent = useQuery({
    queryKey: ["agent", id],
    queryFn: () => ok(api().GET("/v1/agents/{id}", { params: { path: { id } } })),
  });
  const lanes = useQuery(lanesQuery(id));
  const open = useQuery(openAlertsQuery(org, id));
  const recent = useQuery({
    queryKey: ["alerts", org, "agent", id],
    queryFn: () =>
      ok(
        api().GET("/v1/orgs/{org}/alerts", {
          params: { path: { org }, query: { agent: id, limit: 20 } },
        }),
      ),
  });
  const [copied, setCopied] = useState(false);

  if (agent.isPending) return <Loading />;
  if (agent.isError) return <Problem error={agent.error} />;
  const a = agent.data.agent;
  const ls = lanes.data?.lanes ?? [];
  const openAlerts = open.data?.alerts ?? [];
  const nums = (xs: (number | null)[]) => xs.filter((x): x is number => x !== null);
  const storeLag = nums(ls.map((l) => l.store_lag_s));
  const pending = nums(ls.map((l) => l.pending_batches));
  const heartbeat = ls.reduce<string | null>(
    (m, l) => (l.last_heartbeat_at && (!m || l.last_heartbeat_at > m) ? l.last_heartbeat_at : m),
    null,
  );
  const verify = `fr verify agent ${a.agent_id}`;

  return (
    <section>
      <Link href={hrefs.agents(org)} className="text-sm text-slate-500 hover:underline">
        ← Agents
      </Link>
      <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">{a.name}</h1>
          <p className="mt-1 text-sm text-slate-500">
            <AgentId id={a.agent_id} /> · agent key <Hash value={a.agent_key} />
          </p>
        </div>
        <button
          type="button"
          onClick={() =>
            navigator.clipboard.writeText(verify).then(
              () => setCopied(true),
              () => setCopied(false),
            )
          }
          title={verify}
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-600"
        >
          {copied ? "Copied the CLI command" : "Verify independently"}
        </button>
      </div>

      <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Card label="Status">
          {/* "silent" needs the open alerts; until they load, show the stored status */}
          <StatusText
            status={displayStatus(
              a.status,
              openAlerts.some((x) => x.type === "RECORDER_SILENT"),
            )}
          />
        </Card>
        <Card label="Open alerts">
          {open.isPending ? <Pending /> : <SeverityChips counts={severityCounts(openAlerts)} />}
          {openAlerts.length >= OPEN_ALERTS_PAGE && (
            <span className="text-sm text-slate-500">{OPEN_ALERTS_PAGE}+ open</span>
          )}
        </Card>
        <Card label="Store lag">
          {lanes.isPending ? <Pending /> : storeLag.length ? `${Math.max(...storeLag)} s` : "–"}
        </Card>
        <Card label="Pending batches">
          {lanes.isPending ? (
            <Pending />
          ) : pending.length ? (
            pending.reduce((x, y) => x + y, 0)
          ) : (
            "–"
          )}
        </Card>
        <Card label="Last heartbeat">
          {lanes.isPending ? (
            <Pending />
          ) : (
            <span title={heartbeat ?? undefined}>{ago(heartbeat, now)}</span>
          )}
        </Card>
      </div>
      <p className="mt-2 text-sm text-slate-500">
        Privacy level {a.privacy_level} · retention {a.retention_days} d · watch grace{" "}
        {a.watch_grace_s} s
      </p>

      <h2 className="mt-8 text-lg font-semibold">Lanes</h2>
      {lanes.isError ? (
        <Problem error={lanes.error} />
      ) : lanes.isPending ? (
        <Loading />
      ) : ls.length === 0 ? (
        <p className="mt-2 text-slate-500">No recorder has reported yet.</p>
      ) : (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-700">
              <tr>
                <th className="py-2 pr-4 font-medium">Lane</th>
                <th className="py-2 pr-4 font-medium">Recorder</th>
                <th className="py-2 pr-4 font-medium">Last seq</th>
                <th className="py-2 pr-4 font-medium">Last batch</th>
                <th className="py-2 font-medium">Last heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {ls.map((l) => (
                <tr key={l.lane} className="border-b border-slate-100 dark:border-slate-800">
                  <td className="py-2 pr-4 font-mono">{l.lane}</td>
                  <td className="py-2 pr-4">{l.recorder_version ?? "–"}</td>
                  <td className="py-2 pr-4 font-mono">{l.last_seq ? `#${l.last_seq}` : "–"}</td>
                  <td className="py-2 pr-4" title={l.last_batch_at ?? undefined}>
                    {ago(l.last_batch_at, now)}
                  </td>
                  <td className="py-2" title={l.last_heartbeat_at ?? undefined}>
                    {ago(l.last_heartbeat_at, now)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="mt-8 text-lg font-semibold">Recent alerts</h2>
      {recent.isError ? (
        <Problem error={recent.error} />
      ) : !recent.data?.alerts.length ? (
        <p className="mt-2 text-slate-500">{recent.isPending ? "Loading…" : "No alerts."}</p>
      ) : (
        <ul className="mt-2 divide-y divide-slate-100 text-sm dark:divide-slate-800">
          {recent.data.alerts.map((x) => (
            <li key={x.id} className="flex flex-wrap items-center gap-3 py-2">
              <span
                className={`rounded px-1.5 py-0.5 text-xs font-medium ${SEVERITY_CLASS[x.severity]}`}
              >
                {x.severity}
              </span>
              <span className="font-mono">{x.type}</span>
              <span className="text-slate-500">{x.status}</span>
              <span className="text-slate-500" title={x.last_seen_at}>
                {ago(x.last_seen_at, now)}
              </span>
              {x.count > 1 && <span className="text-slate-500">×{x.count}</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
