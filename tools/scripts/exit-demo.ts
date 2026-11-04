// P2 exit demo: a recorder with a configured reader writes its delegation, profile, keygrant and a few
// batches to Arkiv (Rabdi); `decrypt-agent.ts` then opens them with that reader's `.afrkey`.
//
//   node --import ./tools/ts/register.mjs tools/scripts/exit-demo.ts --reader 0x<x25519 pub> [--records 4]
//
// Spends test GLM from AFR_ARKIV_WRITER_KEY (.env): a handful of small creates, capped at 0.05 tGLM.
// Dev identity: a `local:` agent id and an operator key kept in .afr-demo/ (0600, never committed).
// Re-running resumes the same agent and finishes any upload a previous run left pending.
// DoD check: every record carries a fresh canary; afterwards every entity of this agent is read back
// and no attribute or payload may contain it (CLAUDE.md rule 2). Exit 1 if one does.
import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { agentKey } from "../../packages/core/src/index.js";
import { sealKeygrant } from "../../packages/crypto/src/index.js";
import { parseConfig, Recorder } from "../../packages/recorder/src/index.js";
import {
  createArkivStore,
  SCHEMA_NAMES,
  SCHEMA_SPEC,
  type WriteEntry,
  type WriteJournal,
} from "../../packages/store/src/index.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const DIR = join(ROOT, ".afr-demo");
const SPEND_CAP_WEI = 50_000_000_000_000_000n; // 0.05 tGLM

/** Durable WriterQueue journal (L3 §7): one fsync'd JSON file per write, replaced atomically. */
class FileWriteJournal implements WriteJournal {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  async get(id: Hex) {
    const f = join(this.dir, `${id}.json`);
    return existsSync(f) ? (JSON.parse(readFileSync(f, "utf8")) as WriteEntry) : undefined;
  }
  async set(e: WriteEntry) {
    const f = join(this.dir, `${e.id}.json`);
    const fd = openSync(`${f}.tmp`, "w", 0o600);
    writeSync(fd, JSON.stringify(e));
    fsyncSync(fd);
    closeSync(fd);
    renameSync(`${f}.tmp`, f);
  }
}

/** Reads `name` from .afr-demo/, creating it with `make()` (mode 0600) on first use. */
function persisted(name: string, make: () => string): string {
  const f = join(DIR, name);
  if (!existsSync(f)) writeFileSync(f, make(), { mode: 0o600, flag: "wx" });
  return readFileSync(f, "utf8").trim();
}

async function main(): Promise<number> {
  const { values: v } = parseArgs({
    options: { reader: { type: "string" }, records: { type: "string", default: "4" } },
  });
  if (!v.reader || !/^0x[0-9a-f]{64}$/.test(v.reader) || !/^\d{1,2}$/.test(v.records ?? "")) {
    process.stdout.write("usage: exit-demo.ts --reader 0x<64 lowercase hex> [--records n≤99]\n");
    return 2;
  }
  const envFile = join(ROOT, ".env");
  if (existsSync(envFile)) process.loadEnvFile(envFile);
  const accessKey = process.env.ARKIV_ACCESS_KEY;
  const writerKey = process.env.AFR_ARKIV_WRITER_KEY;
  if (!accessKey || !writerKey) {
    process.stdout.write("ARKIV_ACCESS_KEY and AFR_ARKIV_WRITER_KEY are needed in .env\n");
    return 2;
  }
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const agentId = persisted("agent-id", () => `local:${randomUUID()}`);
  const operatorKey = persisted("operator.key", () => generatePrivateKey()) as Hex;

  const store = createArkivStore({
    accessKey,
    writerKey,
    journal: new FileWriteJournal(join(DIR, "writes")),
    spendCapWei: SPEND_CAP_WEI,
  });
  const writer = privateKeyToAccount(writerKey as Hex).address.toLowerCase() as Hex;
  const config = parseConfig(
    {
      version: 1,
      agent: { id: agentId, retention_days: 30 },
      data_dir: join(DIR, "recorder"),
      delegation: { mode: "operator_env" },
      encryption: { readers: [v.reader] },
    },
    {},
  );
  const rec = await Recorder.start({
    config,
    env: { AFR_OPERATOR_KEY: operatorKey },
    autoRotate: false,
    upload: { store, sealKeygrant, writers: [writer], tickMs: 5_000 },
  });
  try {
    await rec.delegationReady();
    const n = Number(v.records);
    const canary = `afr-canary-${randomUUID()}`;
    for (let i = 0; i < n; i++)
      rec.capture({
        type: "tool_call",
        tool: { server: "demo-dex", name: i % 2 ? "swap" : "quote" },
        meta: { event: canary },
        body: {
          args: { pair: "ETH/USDC", amount: `${(i + 1) * 10}`, memo: canary },
          result: { ok: true, i, memo: canary },
        },
      });
    await rec.flush();
    const counts = rec.journal.batchCounts();

    // read back every entity of this agent (all writers): the canary must appear nowhere
    let scanned = 0;
    let leaks = 0;
    const where = { agent_key: { eq: agentKey(agentId) } } as never;
    for (const schema of SCHEMA_NAMES) {
      if (!("agent_key" in SCHEMA_SPEC[schema].attrs)) continue;
      for await (const e of store.query({ schema, where })) {
        scanned++;
        const attrs = JSON.stringify(e.attrs, (_k, x) => (typeof x === "bigint" ? `${x}` : x));
        if (attrs.includes(canary) || Buffer.from(e.payload).toString("latin1").includes(canary))
          leaks++;
      }
    }
    process.stdout.write(
      `${JSON.stringify({ agent_id: agentId, writer, batches: counts, plaintext_check: { entities: scanned, leaks } }, null, 2)}\n` +
        "next: decrypt-agent.ts decrypt --agent <agent_id above> --reader-key reader.afrkey " +
        `--writer ${writer}\n`,
    );
    return (counts.verified ?? 0) > 0 && scanned > 0 && leaks === 0 ? 0 : 1;
  } finally {
    await rec.close();
  }
}

main().then(
  (c) => process.exit(c),
  // codes only: messages can carry the keyed RPC URL
  (e) => {
    process.stderr.write(`exit-demo: ${(e as { code?: string }).code ?? "ERROR"}\n`);
    process.exit(2);
  },
);
