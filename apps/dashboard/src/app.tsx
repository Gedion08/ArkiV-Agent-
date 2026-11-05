// Shell: session check, sidebar (org switcher, navigation, the org's agents, wallet) and the L9 §1 routes
// built so far.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, ChevronsUpDown, LayoutGrid, LogOut } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "./components/link.js";
import { Logo } from "./components/logo.js";
import { btn, EmptyState, Loading, Problem, StatusDot } from "./components/ui.js";
import { agentsQuery, api, type Org, ok } from "./lib/api.js";
import { displayStatus, short } from "./lib/format.js";
import { hrefs, navigate, parseRoute, type Route, usePath } from "./lib/route.js";
import { AgentPage } from "./pages/agent.js";
import { AgentsPage } from "./pages/agents.js";
import { LoginPage } from "./pages/login.js";

export function App() {
  const route = parseRoute(usePath());
  return route.name === "login" ? <LoginPage /> : <Shell route={route} />;
}

function Shell({ route }: { route: Route }) {
  const qc = useQueryClient();
  // a 401 anywhere sends the user to /login (main.tsx)
  const me = useQuery({ queryKey: ["me"], queryFn: () => ok(api().GET("/v1/me")) });
  const orgs = useQuery({
    queryKey: ["orgs"],
    queryFn: () => ok(api().GET("/v1/orgs")),
    enabled: me.isSuccess,
  });
  const logout = useMutation({
    mutationFn: () => ok(api().POST("/v1/auth/logout")),
    onSettled: () => {
      qc.clear();
      navigate("/login", true);
    },
  });

  if (me.isPending)
    return (
      <div className="mx-auto max-w-6xl p-8">
        <Loading />
      </div>
    );
  if (me.isError)
    return (
      <div className="mx-auto max-w-6xl p-8">
        <Problem error={me.error} />
      </div>
    );
  const org = "org" in route ? route.org : undefined;
  const wallet = me.data.user.wallet;
  const signOut = (iconOnly: boolean) => (
    <button
      type="button"
      onClick={() => logout.mutate()}
      disabled={logout.isPending}
      aria-label={iconOnly ? "Sign out" : undefined}
      title="Sign out"
      className={`${btn.ghost} min-h-9 px-2.5`}
    >
      <LogOut aria-hidden className="size-4" />
      {!iconOnly && "Sign out"}
    </button>
  );

  return (
    <div className="min-h-screen md:flex">
      <aside className="flex flex-col gap-5 border-b border-line bg-surface px-3 py-4 md:sticky md:top-0 md:h-screen md:w-64 md:shrink-0 md:overflow-y-auto md:border-r md:border-b-0">
        <div className="flex items-center justify-between gap-2 px-2">
          <Link href="/" className="flex items-center gap-2.5" aria-label="AFR home">
            <Logo />
            <span className="flex flex-col leading-tight">
              <span className="text-[15px] font-semibold tracking-tight">AFR</span>
              <span className="text-xs text-muted">Agent Flight Recorder</span>
            </span>
          </Link>
          <span className="md:hidden">{signOut(false)}</span>
        </div>

        <OrgSwitcher orgs={orgs.data?.orgs ?? []} current={org} />

        {org && (
          <nav aria-label="Main" className="flex flex-col gap-0.5">
            <Link
              href={hrefs.agents(org)}
              aria-current={route.name === "agents" ? "page" : undefined}
              className={`flex min-h-9 items-center gap-2.5 rounded-lg px-2.5 font-medium ${
                route.name === "agents"
                  ? "bg-accent-soft text-accent-soft-fg"
                  : "text-fg-2 hover:bg-raised"
              }`}
            >
              <LayoutGrid aria-hidden className="size-4" />
              Agents
            </Link>
          </nav>
        )}

        {org && <AgentNav org={org} current={route.name === "agent" ? route.id : undefined} />}

        <div className="mt-auto hidden items-center gap-2.5 border-t border-line px-2 pt-4 md:flex">
          <span aria-hidden className="size-7 shrink-0 rounded-full bg-accent-soft" />
          <span className="flex min-w-0 flex-col leading-tight">
            <span className="font-mono text-xs" title={wallet}>
              {short(wallet, 4)}
            </span>
            <span className="text-xs text-muted">Signed in with wallet</span>
          </span>
          <span className="ml-auto">{signOut(true)}</span>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 md:px-8 md:py-8">
          {route.name === "home" ? (
            orgs.isError ? (
              <Problem error={orgs.error} />
            ) : orgs.isPending ? (
              <Loading />
            ) : (
              <Home orgs={orgs.data.orgs} />
            )
          ) : route.name === "agents" ? (
            <AgentsPage org={route.org} />
          ) : route.name === "agent" ? (
            <AgentPage org={route.org} id={route.id} />
          ) : (
            <EmptyState icon={LayoutGrid} title="Page not found">
              <Link href="/" className="text-accent hover:underline">
                Go to your agents
              </Link>
            </EmptyState>
          )}
        </div>
      </main>
    </div>
  );
}

const initials = (name: string) =>
  name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase())
    .join("");

function OrgSwitcher({ orgs, current }: { orgs: Org[]; current: string | undefined }) {
  if (!orgs.length) return null;
  const org = orgs.find((o) => o.id === current);
  return (
    <label className="relative flex min-h-11 items-center gap-2.5 rounded-xl border border-line-strong bg-raised px-2.5 hover:bg-surface">
      <span
        aria-hidden
        className="flex size-7 shrink-0 items-center justify-center rounded-md bg-accent-soft text-[11px] font-semibold text-accent-soft-fg"
      >
        {org ? initials(org.name) : <Building2 className="size-4" />}
      </span>
      <span aria-hidden className="flex min-w-0 flex-1 flex-col leading-tight">
        <span className="truncate font-medium">{org?.name ?? "Choose an organisation"}</span>
        {org && <span className="text-xs text-muted capitalize">{org.role}</span>}
      </span>
      <ChevronsUpDown aria-hidden className="size-4 shrink-0 text-muted" />
      <span className="sr-only">Organisation</span>
      {/* the native select keeps keyboard and screen-reader behaviour; the card above is its face */}
      <select
        value={current ?? ""}
        onChange={(e) => e.target.value && navigate(hrefs.agents(e.target.value))}
        className="absolute inset-0 cursor-pointer opacity-0"
      >
        {!current && <option value="">Choose an organisation</option>}
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name} ({o.role})
          </option>
        ))}
      </select>
    </label>
  );
}

/** The org's agents for quick switching (desktop only; on phones the list page is one tap away). */
function AgentNav({ org, current }: { org: string; current: string | undefined }) {
  const agents = useQuery(agentsQuery(org));
  const list = agents.data?.agents ?? [];
  if (!list.length) return null;
  return (
    <div className="hidden flex-col gap-0.5 md:flex">
      <span className="px-2.5 pb-1.5 text-xs font-medium text-muted">Agents</span>
      {list.map((a) => {
        const s = displayStatus(a.status, a.summary.recorder_silent);
        return (
          <Link
            key={a.id}
            href={hrefs.agent(org, a.id)}
            aria-current={a.id === current ? "page" : undefined}
            className={`flex min-h-8 items-center gap-2.5 rounded-lg px-2.5 ${
              a.id === current
                ? "bg-raised font-medium text-fg shadow-[0_0_0_1px_var(--color-line-strong)]"
                : "text-fg-2 hover:bg-raised"
            }`}
          >
            <StatusDot status={s} />
            <span className="truncate">{a.name}</span>
            <span className="ml-auto text-xs text-muted capitalize">{s}</span>
          </Link>
        );
      })}
    </div>
  );
}

/** `/` → the first org's agents, or create an org when the user has none. */
function Home({ orgs }: { orgs: Org[] }) {
  const first = orgs[0]?.id;
  useEffect(() => {
    if (first) navigate(hrefs.agents(first), true);
  }, [first]);
  return first ? <Loading /> : <CreateOrg />;
}

function CreateOrg() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => ok(api().POST("/v1/orgs", { body: { name: name.trim() } })),
    onSuccess: async (o) => {
      await qc.invalidateQueries({ queryKey: ["orgs"] });
      navigate(hrefs.agents(o.id));
    },
  });
  return (
    <form
      className="mx-auto mt-12 flex max-w-md flex-col gap-5 rounded-2xl border border-line bg-raised p-6"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) create.mutate();
      }}
    >
      <div className="flex flex-col gap-1.5">
        <h1 className="text-xl font-semibold tracking-tight">Create an organisation</h1>
        <p className="text-muted">
          You're not a member of any organisation yet. Create one, or ask an owner to invite you.
        </p>
      </div>
      <label className="flex flex-col gap-1.5 font-medium">
        Name
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={200}
          required
          placeholder="Acme Trading"
          className="min-h-10 rounded-lg border border-line-strong bg-canvas px-3 font-normal placeholder:text-muted"
        />
      </label>
      <button type="submit" disabled={create.isPending} className={btn.primary}>
        Create organisation
      </button>
      {create.isError && <Problem error={create.error} />}
    </form>
  );
}
