// P2-16: decrypt an agent's batches from Arkiv with a reader key (`.afrkey`, L4 §6) and check every hash,
// root, link and signature (precursor of `fr verify`, L7). Read-only: no write can ever be sent.
//
//   node --import ./tools/ts/register.mjs tools/scripts/decrypt-agent.ts keygen --out reader.afrkey
//   node --import ./tools/ts/register.mjs tools/scripts/decrypt-agent.ts decrypt \
//     --agent <agent_id> --reader-key reader.afrkey [--lane 0] [--writer 0x…]… [--out records.json]
//
// `decrypt` needs ARKIV_ACCESS_KEY in .env. Passphrase: AFR_READER_PASSPHRASE, else a hidden prompt.
// Plaintext goes only to --out (mode 0600); stdout gets the summary and findings, never bodies.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { Hex } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { agentKey } from "../../packages/core/src/index.js";
import {
  exportReaderBackup,
  generateReaderKey,
  importReaderBackup,
} from "../../packages/crypto/src/index.js";
import {
  createArkivStore,
  type EvidenceStore,
  MemoryWriteJournal,
} from "../../packages/store/src/index.js";
import { decryptAgent } from "../../packages/verifier/src/index.js";

export interface RunDeps {
  /** Injected in tests; otherwise Arkiv (Rabdi) from .env. */
  store?: EvidenceStore;
  passphrase?: () => Promise<string>;
  out?: (line: string) => void;
}

const USAGE =
  "usage: decrypt-agent.ts keygen --out <file.afrkey> | decrypt --agent <id> --reader-key <file.afrkey> [--lane n] [--writer 0x…]… [--out <file.json>]";

/** Reads a line from the TTY without echoing it. */
function hiddenPrompt(label: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) return Promise.reject(Object.assign(new Error(), { code: "NO_PASSPHRASE" }));
  process.stderr.write(label);
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise((resolve, reject) => {
    let s = "";
    const done = (fn: () => void) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
      process.stderr.write("\n");
      fn();
    };
    const onData = (d: Buffer) => {
      for (const c of d.toString("utf8")) {
        if (c === "\r" || c === "\n") return done(() => resolve(s));
        if (c === "\u0003")
          return done(() => reject(Object.assign(new Error(), { code: "CANCELLED" })));
        if (c === "\u007f") s = s.slice(0, -1);
        else s += c;
      }
    };
    stdin.on("data", onData);
  });
}

const defaultPassphrase = () =>
  process.env.AFR_READER_PASSPHRASE
    ? Promise.resolve(process.env.AFR_READER_PASSPHRASE)
    : hiddenPrompt("reader key passphrase: ");

const json = (v: unknown) =>
  JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2);

function arkivReader(): EvidenceStore | undefined {
  const envFile = new URL("../../.env", import.meta.url);
  if (existsSync(envFile)) process.loadEnvFile(envFile);
  const accessKey = process.env.ARKIV_ACCESS_KEY;
  if (!accessKey) return undefined;
  // read-only: a throwaway account and a zero spend cap, so the writer queue can never send
  return createArkivStore({
    accessKey,
    writerKey: generatePrivateKey(),
    journal: new MemoryWriteJournal(),
    spendCapWei: 0n,
  });
}

/** Returns the exit code: 0 ok, 1 findings, 2 usage or input error. */
export async function run(argv: string[], deps: RunDeps = {}): Promise<number> {
  const out = deps.out ?? ((l: string) => process.stdout.write(`${l}\n`));
  const usage = (msg = USAGE) => {
    out(msg);
    return 2;
  };
  const passphrase = deps.passphrase ?? defaultPassphrase;
  const [cmd, ...rest] = argv;
  let v: { out?: string; agent?: string; "reader-key"?: string; lane?: string; writer?: string[] };
  try {
    ({ values: v } = parseArgs({
      args: rest,
      options: {
        out: { type: "string" },
        agent: { type: "string" },
        "reader-key": { type: "string" },
        lane: { type: "string" },
        writer: { type: "string", multiple: true },
      },
    }));
  } catch {
    return usage();
  }

  if (cmd === "keygen") {
    if (!v.out) return usage();
    if (existsSync(v.out)) return usage(`refusing to overwrite ${v.out}`);
    const pw = await passphrase();
    if (pw.length < 12) return usage("passphrase must be at least 12 characters");
    const key = await generateReaderKey();
    const backup = await exportReaderBackup(key, pw);
    key.priv.fill(0);
    writeFileSync(v.out, `${json(backup)}\n`, { mode: 0o600, flag: "wx" });
    out(json({ reader: backup.x25519_pub, file: v.out }));
    return 0;
  }

  const writers = v.writer ?? [];
  if (
    cmd !== "decrypt" ||
    !v.agent ||
    !v["reader-key"] ||
    (v.lane !== undefined && !/^\d{1,5}$/.test(v.lane)) ||
    !writers.every((w) => /^0x[0-9a-fA-F]{40}$/.test(w))
  )
    return usage();
  if (v.out && existsSync(v.out)) return usage(`refusing to overwrite ${v.out}`);
  let ak: Hex;
  try {
    ak = agentKey(v.agent);
  } catch {
    return usage("invalid --agent");
  }
  const store = deps.store ?? arkivReader();
  if (!store) return usage("ARKIV_ACCESS_KEY missing (.env)");
  let reader: Awaited<ReturnType<typeof importReaderBackup>>;
  try {
    reader = await importReaderBackup(
      JSON.parse(readFileSync(v["reader-key"], "utf8")),
      await passphrase(),
    );
  } catch (e) {
    return usage(`reader key: ${(e as { code?: string }).code ?? "unreadable"}`);
  }
  const report = await decryptAgent({
    store,
    agentKey: ak,
    lane: BigInt(v.lane ?? "0"),
    reader,
    ...(writers.length ? { writers: writers.map((w) => w.toLowerCase() as Hex) } : {}),
  }).finally(() => reader.priv.fill(0));
  if (v.out) writeFileSync(v.out, `${json(report.records)}\n`, { mode: 0o600, flag: "wx" });
  out(
    json({
      ok: report.ok,
      agent_key: ak,
      batches: report.batches,
      records: report.records.length,
      findings: report.findings,
      ...(v.out ? { out: v.out } : {}),
    }),
  );
  return report.ok ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1])
  run(process.argv.slice(2)).then(
    (c) => process.exit(c),
    // codes only: messages can carry untrusted input or the keyed RPC URL
    (e) => {
      process.stderr.write(`decrypt-agent: ${(e as { code?: string }).code ?? "ERROR"}\n`);
      process.exit(2);
    },
  );
