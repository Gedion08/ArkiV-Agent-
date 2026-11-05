// Shell: session check, header with org switcher, and the L9 §1 routes built so far.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "./components/link.js";
import { Loading, Problem } from "./components/ui.js";
import { api, type Org, ok } from "./lib/api.js";
import { short } from "./lib/format.js";
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

  if (me.isPending) return <Loading />;
  if (me.isError) return <Problem error={me.error} />;
  const org = "org" in route ? route.org : undefined;
  const wallet = me.data.user.wallet;

  return (
    <div className="min-h-screen">
      <header className="flex flex-wrap items-center gap-4 border-b border-slate-200 px-4 py-3 dark:border-slate-700">
        <Link href="/" className="font-semibold">
          AFR
        </Link>
        <OrgSwitcher orgs={orgs.data?.orgs ?? []} current={org} />
        <span className="ml-auto hidden font-mono text-sm text-slate-500 sm:inline" title={wallet}>
          {short(wallet, 4)}
        </span>
        <button
          type="button"
          onClick={() => logout.mutate()}
          disabled={logout.isPending}
          className="ml-auto text-sm underline-offset-2 hover:underline sm:ml-0"
        >
          Sign out
        </button>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
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
          <p>Page not found.</p>
        )}
      </main>
    </div>
  );
}

function OrgSwitcher({ orgs, current }: { orgs: Org[]; current: string | undefined }) {
  if (!orgs.length) return null;
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="sr-only">Organisation</span>
      <select
        value={current ?? ""}
        onChange={(e) => e.target.value && navigate(hrefs.agents(e.target.value))}
        className="rounded border border-slate-300 bg-transparent px-2 py-1 dark:border-slate-600"
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
      className="max-w-md"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) create.mutate();
      }}
    >
      <h1 className="text-xl font-semibold">Create an organisation</h1>
      <p className="mt-1 text-slate-600 dark:text-slate-400">
        You're not a member of any organisation yet. Create one, or ask an owner to invite you.
      </p>
      <label className="mt-4 block text-sm">
        Name
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={200}
          required
          className="mt-1 block w-full rounded border border-slate-300 bg-transparent px-2 py-1 dark:border-slate-600"
        />
      </label>
      <button
        type="submit"
        disabled={create.isPending}
        className="mt-4 rounded-md bg-slate-900 px-4 py-2 text-white disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900"
      >
        Create
      </button>
      {create.isError && <Problem error={create.error} />}
    </form>
  );
}
