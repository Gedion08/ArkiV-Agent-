// fr CLI (P1-16): local `fr journal verify` walks the SQLite chain; no network.
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import type { AfrError } from "@afr/core";
import { expandHome, laneDir, loadConfig, parseConfig, verifyJournal } from "@afr/recorder";

export const PACKAGE_NAME = "@afr/cli";

const USAGE = `usage:
  fr journal verify [--config FILE | --journal PATH]

Without either flag, the dev identity in $AFR_DATA_DIR (default ~/.afr) written by \`fr-proxy run\` is used.`;

type Out = (s: string) => void;

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
): Promise<number> {
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
