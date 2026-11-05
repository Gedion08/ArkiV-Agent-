// L9 §4.2 agent overview from API data. The decrypted cards (value moved), the mini timeline and the verify
// badge need the reader key and workers (P4-09 … P4-14).
import { useQuery } from "@tanstack/react-query";
import { Bell, Check, Copy, Radio } from "lucide-react";
import { useState } from "react";
import {
  AgentId,
  btn,
  EmptyState,
  Hash,
  Loading,
  PageHeader,
  Panel,
  Problem,
  SeverityChips,
  SeverityPill,
  Skeleton,
  Stat,
  StatusBadge,
  useNow,
} from "../components/ui.js";
import {
  type Activity,
  activityQuery,
  api,
  lanesQuery,
  OPEN_ALERTS_PAGE,
  ok,
  openAlertsQuery,
} from "../lib/api.js";
import { activityWindow, ago, count, displayStatus, severityCounts } from "../lib/format.js";
import { hrefs } from "../lib/route.js";

export function AgentPage({ org, id }: { org: string; id: string }) {
  const now = useNow();
  const agent = useQuery({
    queryKey: ["agent", id],
    queryFn: () => ok(api().GET("/v1/agents/{id}", { params: { path: { id } } })),
  });
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => ok(api().GET("/v1/orgs")) });
  const lanes = useQuery(lanesQuery(id));
  const activity = useQuery(activityQuery(id));
  const open = useQuery(openAlertsQuery(org, id));
  const recent = useQuery({
    queryKey: ["alerts", org, "agent", id],
    queryFn: () =>
      ok(
        api().GET("/v1/orgs/{org}/alerts", {
          params: { path: { org }, query: { agent: id, limit: 6 } },
        }),
      ),
  });
  const [copied, setCopied] = useState(false);

  if (agent.isPending) return <Loading rows={6} />;
  if (agent.isError) return <Problem error={agent.error} />;
  const a = agent.data.agent;
  const orgName = orgs.data?.orgs.find((o) => o.id === org)?.name ?? "Organisation";
  const ls = lanes.data?.lanes ?? [];
  const openAlerts = open.data?.alerts ?? [];
  const nums = (xs: (number | null)[]) => xs.filter((x): x is number => x !== null);
  const storeLag = nums(ls.map((l) => l.store_lag_s));
  const pending = nums(ls.map((l) => l.pending_batches)).reduce((x, y) => x + y, 0);
  const heartbeat = ls.reduce<string | null>(
    (m, l) => (l.last_heartbeat_at && (!m || l.last_heartbeat_at > m) ? l.last_heartbeat_at : m),
    null,
  );
  const versions = [...new Set(ls.map((l) => l.recorder_version).filter(Boolean))];
  const act = activity.data ? activityWindow(activity.data.hours) : undefined;
  const verify = `fr verify agent ${a.agent_id}`;
  // "silent" needs the open alerts; until they load, show the stored status
  const status = displayStatus(
    a.status,
    openAlerts.some((x) => x.type === "RECORDER_SILENT"),
  );

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        crumbs={[
          { label: orgName },
          { label: "Agents", href: hrefs.agents(org) },
          { label: a.name },
        ]}
        title={a.name}
        badge={<StatusBadge status={status} />}
        meta={
          <>
            <AgentId id={a.agent_id} />
            <span>
              Agent key <Hash value={a.agent_key} n={4} />
            </span>
            <span>
              Privacy level {a.privacy_level} · {a.retention_days}-day retention · {a.watch_grace_s}{" "}
              s watch grace
            </span>
          </>
        }
        actions={
          <button
            type="button"
            title={verify}
            className={btn.secondary}
            onClick={() =>
              navigator.clipboard.writeText(verify).then(
                () => setCopied(true),
                () => setCopied(false),
              )
            }
          >
            {copied ? (
              <Check aria-hidden className="size-4 text-ok" />
            ) : (
              <Copy aria-hidden className="size-4" />
            )}
            {copied ? "Copied the CLI command" : "Verify independently"}
          </button>
        }
      />

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Recorded actions · 24 h"
          loading={activity.isPending}
          value={act ? count(act.total) : "–"}
          sub={
            act?.changePct == null
              ? "No earlier day to compare"
              : `${act.changePct >= 0 ? "+" : ""}${act.changePct}% on the previous 24 h`
          }
        />
        <Stat
          label="Open alerts"
          loading={open.isPending}
          value={openAlerts.length >= OPEN_ALERTS_PAGE ? `${OPEN_ALERTS_PAGE}+` : openAlerts.length}
          sub={<SeverityChips counts={severityCounts(openAlerts)} />}
        />
        <Stat
          label="Store lag"
          loading={lanes.isPending}
          value={storeLag.length ? `${Math.max(...storeLag)} s` : "–"}
          sub={`${pending} ${pending === 1 ? "batch" : "batches"} pending`}
        />
        <Stat
          label="Last heartbeat"
          loading={lanes.isPending}
          value={<span title={heartbeat ?? undefined}>{ago(heartbeat, now)}</span>}
          sub={
            ls.length
              ? `${ls.length} ${ls.length === 1 ? "lane" : "lanes"}${versions.length ? ` · recorder ${versions.join(", ")}` : ""}`
              : "No recorder yet"
          }
        />
      </div>

      <div className="flex flex-wrap gap-4">
        <Panel
          title="Activity"
          description="Recorded actions per hour, last 24 h"
          className="flex-[3_1_520px]"
          actions={<Legend />}
        >
          {activity.isError ? (
            <Problem error={activity.error} />
          ) : !act ? (
            <Skeleton className="h-[190px] w-full" />
          ) : (
            <ActivityChart
              hours={act.shown}
              total={act.total}
              unlogged={act.unlogged}
              peak={act.peak}
            />
          )}
        </Panel>

        <Panel title="Recent alerts" className="flex-[2_1_340px]">
          {recent.isError ? (
            <Problem error={recent.error} />
          ) : recent.isPending ? (
            <Loading rows={3} />
          ) : !recent.data.alerts.length ? (
            <EmptyState icon={Bell} title="No alerts">
              The watcher raises one when something needs a look.
            </EmptyState>
          ) : (
            <ul className="-mx-2 flex flex-col">
              {recent.data.alerts.map((x) => (
                <li
                  key={x.id}
                  className="flex flex-col gap-1 border-t border-line px-2 py-2.5 first:border-t-0"
                >
                  <span className="flex items-center gap-2">
                    <SeverityPill severity={x.severity} />
                    <span className="truncate font-mono text-xs font-medium">{x.type}</span>
                    <span
                      className="ml-auto text-xs whitespace-nowrap text-muted"
                      title={x.last_seen_at}
                    >
                      {ago(x.last_seen_at, now)}
                    </span>
                  </span>
                  <span className="text-xs text-muted">
                    {x.status[0]?.toUpperCase() + x.status.slice(1)}
                    {x.count > 1 && ` · ${x.count} occurrences`}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Lanes" description="One hash chain per recorder lane">
        {lanes.isError ? (
          <Problem error={lanes.error} />
        ) : lanes.isPending ? (
          <Loading rows={2} />
        ) : ls.length === 0 ? (
          <EmptyState icon={Radio} title="No recorder has reported yet">
            Lanes appear once the agent's recorder sends its first batch or heartbeat.
          </EmptyState>
        ) : (
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-[13px]">
              <thead className="text-muted">
                <tr>
                  {[
                    "Lane",
                    "Recorder",
                    "Last seq",
                    "Last batch",
                    "Heartbeat",
                    "Pending",
                    "Store lag",
                  ].map((h) => (
                    <th key={h} className="px-5 py-2 font-medium whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-line border-t border-line">
                {ls.map((l) => (
                  <tr key={l.lane}>
                    <td className="px-5 py-2.5 font-mono">{l.lane}</td>
                    <td className="px-5 py-2.5">{l.recorder_version ?? "–"}</td>
                    <td className="px-5 py-2.5 font-mono">
                      {l.last_seq ? count(Number(l.last_seq)) : "–"}
                    </td>
                    <td className="px-5 py-2.5" title={l.last_batch_at ?? undefined}>
                      {ago(l.last_batch_at, now)}
                    </td>
                    <td className="px-5 py-2.5" title={l.last_heartbeat_at ?? undefined}>
                      {ago(l.last_heartbeat_at, now)}
                    </td>
                    <td className="px-5 py-2.5">{l.pending_batches ?? "–"}</td>
                    <td className="px-5 py-2.5">
                      {l.store_lag_s == null ? "–" : `${l.store_lag_s} s`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

const Legend = () => (
  <span className="flex gap-3.5 text-xs text-muted">
    <span className="flex items-center gap-1.5">
      <span aria-hidden className="size-2.5 rounded-sm bg-accent" />
      Recorded
    </span>
    <span className="flex items-center gap-1.5">
      <Triangle />
      Unlogged tx
    </span>
  </span>
);

const Triangle = () => (
  <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden className="fill-bad">
    <path d="M5 0 10 10H0z" />
  </svg>
);

const hour = (iso: string) =>
  new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });

function ActivityChart({
  hours,
  total,
  unlogged,
  peak,
}: {
  hours: Activity["hours"];
  total: number;
  unlogged: number;
  peak: number;
}) {
  const mid = hours[Math.floor(hours.length / 2)];
  const label = `Bar chart of recorded actions per hour over the last ${hours.length} hours: ${count(total)} in total, at most ${count(peak)} in one hour${unlogged ? `, and ${unlogged} unlogged ${unlogged === 1 ? "transaction" : "transactions"}` : ""}.`;
  return (
    <div className="flex flex-col gap-2">
      <div
        role="img"
        aria-label={label}
        className="flex h-[170px] items-end gap-[3px] border-b border-line pt-4"
      >
        {hours.map((h) => (
          <div
            key={h.start}
            title={`${hour(h.start)} · ${count(h.actions)} actions${h.unlogged ? ` · ${h.unlogged} unlogged` : ""}`}
            className="flex h-full min-w-0 flex-1 flex-col items-center justify-end gap-1"
          >
            {h.unlogged > 0 && <Triangle />}
            <div
              className="w-full rounded-t-[3px] bg-accent opacity-85 transition-opacity hover:opacity-100"
              style={{
                height: `${peak ? Math.max(h.actions ? 3 : 0, (h.actions / peak) * 100) : 0}%`,
              }}
            />
          </div>
        ))}
      </div>
      <div aria-hidden className="flex justify-between text-xs text-muted">
        <span>{hours[0] && hour(hours[0].start)}</span>
        <span>{mid && hour(mid.start)}</span>
        <span>Now</span>
      </div>
      {total === 0 && (
        <p className="text-[13px] text-muted">No actions recorded in the last 24 hours.</p>
      )}
    </div>
  );
}
