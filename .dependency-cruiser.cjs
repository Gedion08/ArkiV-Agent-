// Layer dependency rule: docs/01-architecture/ARCHITECTURE.md §3.
// ALLOWED lists the internal packages each package may import. Anything else is a violation.
const ALLOWED = {
  core: [],
  log: [],
  "test-vectors": ["core"],
  crypto: ["core"],
  store: ["core", "log"],
  policy: ["core"],
  identity: ["core"],
  client: ["core"],
  recorder: ["core", "crypto", "store", "policy", "log"],
  sdk: ["core", "crypto", "store", "policy", "log", "recorder"],
  verifier: ["core", "crypto", "store", "identity"],
};

const packageRules = Object.entries(ALLOWED).map(([pkg, allowed]) => ({
  name: `layer-${pkg}`,
  comment: `packages/${pkg} may only import: ${allowed.join(", ") || "nothing internal"}`,
  severity: "error",
  from: { path: `^packages/${pkg}/` },
  to: {
    path: "^packages/([^/]+)/",
    pathNot: [`^packages/(${[pkg, ...allowed].join("|")})/`],
  },
}));

module.exports = {
  forbidden: [
    {
      name: "packages-not-to-apps",
      comment: "Lower layers never import apps",
      severity: "error",
      from: { path: "^packages/" },
      to: { path: "^apps/" },
    },
    {
      name: "apps-not-to-apps",
      comment: "Apps import packages, never other apps",
      severity: "error",
      from: { path: "^apps/([^/]+)/" },
      to: { path: "^apps/([^/]+)/", pathNot: "^apps/$1/" },
    },
    {
      name: "core-is-pure",
      comment: "packages/core: no Node built-ins (CLAUDE.md rule 3)",
      severity: "error",
      from: { path: "^packages/core/src/" },
      to: { dependencyTypes: ["core"] },
    },
    ...packageRules,
    { name: "no-circular", severity: "error", from: {}, to: { circular: true } },
    { name: "not-to-unresolvable", severity: "error", from: {}, to: { couldNotResolve: true } },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    exclude: { path: "(^|/)(dist|node_modules)/" },
    tsConfig: { fileName: "tsconfig.base.json" },
    tsPreCompilationDeps: true,
    enhancedResolveOptions: {
      exportsFields: ["exports"],
      conditionNames: ["@afr/source", "import", "types", "default"],
      extensions: [".ts", ".js"],
    },
  },
};
