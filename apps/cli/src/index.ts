// fr CLI: local `fr journal verify` walks the SQLite chain (P1-16, no network); verify agent, prove,
// agent show and keys reader read Arkiv and the chains (P3-10, remote.ts).
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import type { AfrError } from "@afr/core";
import { expandHome, laneDir, loadConfig, parseConfig, verifyJournal } from "@afr/recorder";
import {
  agentShowCommand,
  defaultPassphrase,
  keysReaderCommand,
  type NetDeps,
  proveCommand,
  UsageError,
  verifyCommand,
} from "./remote.js";

export { type NetDeps, UsageError } from "./remote.js";

export const PACKAGE_NAME = "@afr/cli";

const USAGE = `usage:
  fr journal verify [--config FILE | --journal PATH]
  fr verify agent <agentId> [--lane N] [--reader-key FILE] [--json] [--strict]
                  [--writer 0x… ...] [--no-writer-filter] [--identity-rpc URL] [--base-rpc URL]
                  [--operator 0x…  (local: agents)]
  fr prove <agentId> <seq> --out proof.json [--lane N] [--no-writer-filter] [--identity-rpc URL]
  fr agent show <agentId> [--json] [--identity-rpc URL]
  fr keys reader new --out FILE.afrkey | show FILE.afrkey

verify agent exits 0 PASS, 1 PASS_WITH_WARNINGS (2 with --strict), 2 FAIL, 3 usage or infra error.
Arkiv reads need ARKIV_ACCESS_KEY; reader-key passphrases come from AFR_READER_PASSPHRASE or a prompt.

Without either flag, the dev identity in $AFR_DATA_DIR (default ~/.afr) written by \`fr-proxy run\` is used.`;

type Out = (s: string) => void;

const REMOTE = new Set(["verify", "prove", "agent", "keys"]);

/** --journal, else the config's lane dir, else the fr-proxy dev identity. */
function journalPath(v: { config?: string; journal?: string }, env: NodeJS.ProcessEnv): string {
  if (v.journal) return v.journal;
  if (v.config) return `${laneDir(loadConfig(v.config, env))}/journal.sqlite`;
  const dir = expandHome(env.AFR_DATA_DIR ?? "~/.afr");
  const idFile = `${dir}/dev-agent-id`;
  if (!existsSync(idFile))
    throw new Error(`no --config/--journal and no dev identity at ${idFile}`);
  const id = readFileSync(idFile, "utf8").trim();
  return `${laneDir(parseConfig({ version: 1, agent: { id }, data_dir: dir }, {}))}/journal.sqlite`;
}

export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  print: Out = (s) => process.stdout.write(s),
  printErr: Out = (s) => process.stderr.write(s),
  deps: NetDeps = {},
): Promise<number> {
  if (REMOTE.has(argv[0] ?? "")) return remote(argv, env, print, printErr, deps);
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        config: { type: "string" },
        journal: { type: "string" },
        help: { type: "boolean" },
      },
    });
  } catch (e) {
    printErr(`${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }
  const { positionals, values } = parsed;
  if (values.help) {
    printErr(`${USAGE}\n`);
    return 0;
  }
  if (positionals[0] !== "journal" || positionals[1] !== "verify") {
    printErr(`${USAGE}\n`);
    return 2;
  }
  try {
    const report = await verifyJournal(
      journalPath(values as { config?: string; journal?: string }, env),
    );
    print(`${JSON.stringify(report, null, 2)}\n`);
    return report.ok ? 0 : 1;
  } catch (e) {
    printErr(`${(e as AfrError).code ? `${(e as AfrError).code}: ` : ""}${(e as Error).message}\n`);
    return 2;
  }
}

/** L7 §5 exit codes: usage and infrastructure errors (RPC, Arkiv down) are 3, never FAIL. */
async function remote(
  argv: string[],
  env: NodeJS.ProcessEnv,
  print: Out,
  printErr: Out,
  deps: NetDeps,
): Promise<number> {
  const d = { passphrase: defaultPassphrase(env), ...deps };
  try {
    const { positionals: p, values: v } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        lane: { type: "string" },
        "reader-key": { type: "string" },
        json: { type: "boolean" },
        strict: { type: "boolean" },
        "no-writer-filter": { type: "boolean" },
        writer: { type: "string", multiple: true },
        "identity-rpc": { type: "string" },
        "base-rpc": { type: "string" },
        operator: { type: "string" },
        out: { type: "string" },
        help: { type: "boolean" },
      },
    });
    if (v.help) {
      printErr(`${USAGE}\n`);
      return 0;
    }
    if (p[0] === "verify" && p[1] === "agent") return await verifyCommand(p[2], v, env, d, print);
    if (p[0] === "prove") return await proveCommand(p[1], p[2], v, env, d, print);
    if (p[0] === "agent" && p[1] === "show") return await agentShowCommand(p[2], v, d, print);
    if (p[0] === "keys" && p[1] === "reader")
      return await keysReaderCommand(p[2], p[3], v, d, print);
    throw new UsageError("unknown command");
  } catch (e) {
    // code only for infra errors: messages from RPC libraries can carry URLs (keyed RPC endpoints)
    const msg =
      e instanceof UsageError || String((e as { code?: string }).code).startsWith("ERR_PARSE_ARGS")
        ? (e as Error).message
        : `infrastructure error ${(e as AfrError).code ?? (e as Error).name}`;
    printErr(`${msg}\n${e instanceof UsageError ? `${USAGE}\n` : ""}`);
    return 3;
  }
}
