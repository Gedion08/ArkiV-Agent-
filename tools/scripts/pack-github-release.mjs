// P3 DoD without an npm org: packs @afr/cli and its workspace closure as tarballs for one GitHub Release,
// with every @afr/* dependency pointing at its sibling tarball's release URL, so
//   npx https://github.com/<repo>/releases/download/<tag>/afr-cli-<v>.tgz verify agent …
// installs the whole set from the release and the rest from npm. Build first (pnpm --filter "@afr/cli..." build).
//
//   node tools/scripts/pack-github-release.mjs --repo Gedion08/ArkiV-Agent- --tag cli-v0.1.0 --out DIR
//
// shortcut: no provenance (that needs the npm registry + an Actions OIDC token, release-cli.yml);
// SHA256SUMS is written next to the tarballs. Switch to release-cli.yml once the @afr org exists.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values: v } = parseArgs({
  options: { repo: { type: "string" }, tag: { type: "string" }, out: { type: "string" } },
});
if (!/^[\w.-]+\/[\w.-]+$/.test(v.repo ?? "") || !/^[\w.-]+$/.test(v.tag ?? "") || !v.out) {
  process.stdout.write("usage: pack-github-release.mjs --repo OWNER/NAME --tag TAG --out DIR\n");
  process.exit(2);
}
const root = resolve(import.meta.dirname, "../..");
const out = resolve(v.out);
if (existsSync(out)) throw new Error(`refusing to reuse ${out}`);
mkdirSync(out, { recursive: true });
const base = `https://github.com/${v.repo}/releases/download/${v.tag}`;
const dirs = execFileSync("pnpm", ["--filter", "@afr/cli...", "exec", "pwd"], { cwd: root })
  .toString()
  .trim()
  .split("\n");
const pkgs = dirs.map((d) => ({ dir: d, json: JSON.parse(readFileSync(join(d, "package.json"))) }));
const file = (p) => `${p.json.name.slice(1).replace("/", "-")}-${p.json.version}.tgz`;
const byName = new Map(pkgs.map((p) => [p.json.name, p]));

for (const p of pkgs) {
  // a staged copy (dist + metadata), never the workspace's own package.json
  const stage = join(out, ".stage", p.json.name.replace("/", "_"));
  mkdirSync(stage, { recursive: true });
  execFileSync("cp", ["-R", join(p.dir, "dist"), stage]);
  copyFileSync(join(root, "LICENSE"), join(stage, "LICENSE"));
  if (existsSync(join(p.dir, "README.md")))
    copyFileSync(join(p.dir, "README.md"), join(stage, "README.md"));
  const deps = {};
  for (const [k, spec] of Object.entries(p.json.dependencies ?? {})) {
    const sib = byName.get(k);
    if (k.startsWith("@afr/") && !sib) throw new Error(`${k} is not in the @afr/cli closure`);
    deps[k] = sib ? `${base}/${file(sib)}` : spec;
  }
  const { devDependencies, scripts, publishConfig, ...rest } = p.json;
  const json = {
    ...rest,
    dependencies: deps,
    files: ["dist"],
    repository: {
      type: "git",
      url: `git+https://github.com/${v.repo}.git`,
      directory: p.dir.slice(root.length + 1),
    },
  };
  writeFileSync(join(stage, "package.json"), `${JSON.stringify(json, null, 2)}\n`);
  execFileSync("npm", ["pack", "--silent", "--pack-destination", out], { cwd: stage });
}
const tgz = readdirSync(out)
  .filter((f) => f.endsWith(".tgz"))
  .sort();
const want = pkgs.map(file).sort();
if (JSON.stringify(tgz) !== JSON.stringify(want))
  throw new Error(`packed ${tgz.join(",")}, expected ${want.join(",")}`);
const sums = tgz.map(
  (f) =>
    `${createHash("sha256")
      .update(readFileSync(join(out, f)))
      .digest("hex")}  ${f}`,
);
writeFileSync(join(out, "SHA256SUMS"), `${sums.join("\n")}\n`);
process.stdout.write(
  `${JSON.stringify({ out, tarballs: tgz, cli: `${base}/${file(byName.get("@afr/cli"))}` }, null, 2)}\n`,
);
