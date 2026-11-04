// P3-13 testnet e2e (L11 §3, nightly `testnet-e2e.yml`): the P2 demo plus anchoring and verification,
// end to end on the real networks. A fresh `local:` agent records a few tool calls; its batches go to
// Arkiv (Rabdi) and its checkpoint notices to an in-process API on Postgres; the anchor service anchors
// them on Base Sepolia; then the verifier checks the agent in full mode (reader key) and must PASS.
//
//   node --import ./tools/ts/register.mjs tools/e2e/scripts/testnet-e2e.ts [--records 4] [--report out.json]
//
// env (.env is read when present): AFR_PG_URL, ARKIV_ACCESS_KEY, AFR_ARKIV_WRITER_KEY, AFR_ANCHOR_KEY (on the
// RecorderAnchor allowlist, funded on Base Sepolia), AFR_ANCHOR_RPC_URL (or BASE_SEPOLIA_RPC_URL).
// Spends test GLM (capped at 0.05) and one anchor tx of Base Sepolia ETH. Exit 0 PASS, 1 FAIL, 2 config.
// Every run gets a new agent, operator key and Postgres schema, so a failed night never blocks the next.
// The schema is dropped on success and kept on failure (named in the report) for debugging.
//
// --agent eip155:84532:<registry>:<id> records for a real ERC-8004 agent instead (operator key in
// AFR_OPERATOR_KEY) and verifies against its on-chain registration: this seeds the README demo agent.
// Its journal is kept in .afr-demo/agents/<agentKey>, and a second run for the same agent is refused:
// a fresh journal would restart the lane at seq 0, an equivocation.
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import pg from "pg";
import { createPublicClient, type Hex, http, type PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import {
  AnchorChain,
  AnchorService,
  type AnchorSigner,
  PgAnchorDb,
  PgWriteJournal,
  RECORDER_ANCHOR_ABI,
} from "../../../apps/anchor/src/index.js";
import {
  buildServer,
  localKeyWrapper,
  migrate,
  newRecorderKey,
} from "../../../apps/api/src/index.js";
import {
  ANCHOR_CONTRACTS,
  agentKey,
  CHAINS,
  isLocalAgentId,
  parseAgentId,
} from "../../../packages/core/src/index.js";
import { generateReaderKey, sealKeygrant } from "../../../packages/crypto/src/index.js";
import {
  AFR_SERVICE_NAME,
  AFR_SERVICE_VERSION,
  type AfrService,
} from "../../../packages/identity/src/index.js";
import { parseConfig, Recorder } from "../../../packages/recorder/src/index.js";
import { createArkivStore, SCHEMA_NAMES, SCHEMA_SPEC } from "../../../packages/store/src/index.js";
import {
  rpcAnchorReader,
  rpcIdentityReader,
  staticIdentityReader,
  verifyAgent,
} from "../../../packages/verifier/src/index.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const SPEND_CAP_WEI = 50_000_000_000_000_000n; // 0.05 tGLM
const ANCHOR_DEADLINE_MS = 10 * 60_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function readEnv() {
  try {
    process.loadEnvFile(join(ROOT, ".env"));
  } catch {} // CI passes env directly
  const e = process.env;
  const env = {
    pg: e.AFR_PG_URL,
    accessKey: e.ARKIV_ACCESS_KEY,
    writerKey: e.AFR_ARKIV_WRITER_KEY,
    anchorKey: e.AFR_ANCHOR_KEY,
    rpc: e.AFR_ANCHOR_RPC_URL || e.BASE_SEPOLIA_RPC_URL,
  };
  const names = {
    pg: "AFR_PG_URL",
    accessKey: "ARKIV_ACCESS_KEY",
    writerKey: "AFR_ARKIV_WRITER_KEY",
    anchorKey: "AFR_ANCHOR_KEY",
    rpc: "AFR_ANCHOR_RPC_URL",
  } as const;
  const missing = (Object.keys(env) as (keyof typeof env)[]).filter((k) => !env[k]);
  return missing.length ? missing.map((k) => names[k]) : (env as Record<keyof typeof env, string>);
}

async function main(): Promise<number> {
  const { values: v } = parseArgs({
    options: {
      records: { type: "string", default: "4" },
      report: { type: "string" },
      agent: { type: "string" },
    },
  });
  const usage = (why: string) => {
    process.stdout.write(
      `${why}\nusage: testnet-e2e.ts [--records 1..99] [--report out.json] [--agent eip155:84532:…]\n`,
    );
    return 2;
  };
  if (!/^[1-9]\d?$/.test(v.records ?? "")) return usage("bad --records");
  const env = readEnv();
  if (Array.isArray(env)) return usage(`missing env: ${env.join(", ")}`);
  let real: { id: string; operatorKey: Hex; dir: string } | undefined;
  if (v.agent) {
    try {
      if (isLocalAgentId(v.agent) || parseAgentId(v.agent).chainId !== BigInt(CHAINS.BASE_SEPOLIA))
        return usage("--agent must be a Base Sepolia ERC-8004 agent id");
    } catch {
      return usage("--agent is not a valid agent id");
    }
    const operatorKey = process.env.AFR_OPERATOR_KEY;
    if (!/^0x[0-9a-fA-F]{64}$/.test(operatorKey ?? ""))
      return usage("--agent needs AFR_OPERATOR_KEY");
    const dir = join(ROOT, ".afr-demo", "agents", agentKey(v.agent).slice(2));
    if (existsSync(dir))
      return usage(`${v.agent} was already recorded (${dir}): refusing a second lane-0 history`);
    real = { id: v.agent, operatorKey: operatorKey as Hex, dir };
  }
  const started = Date.now();
  const report: Record<string, unknown> = { scenario: "afr-testnet-e2e/1", ok: false };
  const finish = (ok: boolean) => {
    report.ok = ok;
    report.duration_s = Math.round((Date.now() - started) / 1000);
    const out = `${JSON.stringify(report, null, 2)}\n`;
    process.stdout.write(out);
    if (v.report) writeFileSync(v.report, out);
    return ok ? 0 : 1;
  };

  // Base Sepolia first: stop before any Arkiv spend if the anchor key can't anchor
  const contract = ANCHOR_CONTRACTS[CHAINS.BASE_SEPOLIA]?.at(-1)?.address as Hex;
  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(env.rpc, { retryCount: 3 }),
  }) as PublicClient;
  const signer = privateKeyToAccount(env.anchorKey as Hex) as AnchorSigner;
  const [allowed, balance] = await Promise.all([
    publicClient.readContract({
      address: contract,
      abi: RECORDER_ANCHOR_ABI,
      functionName: "isRecorder",
      args: [signer.address],
    }),
    publicClient.getBalance({ address: signer.address }),
  ]);
  report.anchor_signer = signer.address.toLowerCase();
  if (!allowed || balance === 0n) {
    report.error = allowed ? "ANCHOR_KEY_UNFUNDED" : "NOT_RECORDER";
    return finish(false);
  }

  const schema = `afr_e2e_${randomBytes(4).toString("hex")}`;
  report.pg_schema = schema;
  const admin = new pg.Pool({ connectionString: env.pg, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({
    connectionString: env.pg,
    max: 4,
    options: `-c search_path=${schema}`,
  });
  let ok = false;
  try {
    await migrate(pool);
    const app = await buildServer({
      pool,
      siweDomain: "e2e.afr.test",
      keys: localKeyWrapper(randomBytes(32)),
    });
    const apiUrl = await app.listen({ port: 0, host: "127.0.0.1" });

    const agentId = real?.id ?? `local:${randomUUID()}`;
    const operatorKey = real?.operatorKey ?? generatePrivateKey();
    if (real) mkdirSync(real.dir, { recursive: true, mode: 0o700 }); // from here on, a rerun is refused
    const reader = await generateReaderKey();
    report.agent_id = agentId;
    // the org, agent and recorder key the dashboard would create
    const org = (await pool.query("INSERT INTO orgs (name) VALUES ('e2e') RETURNING id")).rows[0]
      .id;
    const agent = (
      await pool.query(
        "INSERT INTO agents (org_id, agent_id, agent_key, name) VALUES ($1, $2, $3, 'e2e') RETURNING id",
        [org, agentId, Buffer.from(agentKey(agentId).slice(2), "hex")],
      )
    ).rows[0].id;
    const key = newRecorderKey();
    await pool.query(
      "INSERT INTO recorder_keys (id, org_id, agent_id, secret_hash, lanes) VALUES ($1, $2, $3, $4, '{0}')",
      [key.id, org, agent, key.secretHash],
    );

    // one store (one WriterQueue, one nonce sequence) for both the recorder's and the anchor service's writes
    const store = createArkivStore({
      accessKey: env.accessKey,
      writerKey: env.writerKey,
      journal: new PgWriteJournal(pool),
      spendCapWei: SPEND_CAP_WEI,
    });
    const writer = privateKeyToAccount(env.writerKey as Hex).address.toLowerCase() as Hex;
    const rec = await Recorder.start({
      config: parseConfig(
        {
          version: 1,
          agent: { id: agentId, retention_days: 30 },
          data_dir: real?.dir ?? mkdtempSync(join(tmpdir(), "afr-e2e-")),
          delegation: { mode: "operator_env" },
          encryption: { readers: [reader.pub] },
          batch: { heartbeat: false }, // nothing after the anchored checkpoint, so verify sees no tail
          api: { url: apiUrl },
        },
        {},
      ),
      env: { AFR_OPERATOR_KEY: operatorKey, AFR_API_KEY: key.token },
      autoRotate: false,
      upload: { store, sealKeygrant, writers: [writer], tickMs: 5_000 },
    });
    try {
      await rec.delegationReady();
      const canary = `afr-canary-${randomUUID()}`;
      for (let i = 0; i < Number(v.records); i++)
        rec.capture({
          type: "tool_call",
          tool: { server: "demo-dex", name: i % 2 ? "swap" : "quote" },
          meta: { event: canary },
          body: {
            args: { pair: "ETH/USDC", amount: `${(i + 1) * 10}`, memo: canary },
            result: { ok: true, i, memo: canary },
          },
        });
      await rec.flush(); // uploads, then drains the outbox: the checkpoint notices are in Postgres
      report.batches = rec.journal.batchCounts();

      const svc = new AnchorService({
        db: new PgAnchorDb(pool),
        store,
        chain: new AnchorChain({ publicClient, chain: baseSepolia, contract, signer }),
        cadenceMs: 0,
      });
      const latest = async () =>
        (
          await pool.query<{ seq_to: string; status: string; anchor_tx: Buffer | null }>(
            "SELECT seq_to::text, status, anchor_tx FROM checkpoints ORDER BY seq_to DESC LIMIT 1",
          )
        ).rows[0];
      let last = await latest();
      for (const deadline = Date.now() + ANCHOR_DEADLINE_MS; ; ) {
        if (!last || last.status === "anchored" || last.status === "rejected") break;
        if (Date.now() > deadline) break;
        await svc.tick();
        last = await latest();
        if (last?.status !== "anchored") await sleep(10_000);
      }
      report.checkpoint = last
        ? {
            seq_to: last.seq_to,
            status: last.status,
            ...(last.anchor_tx ? { anchor_tx: `0x${last.anchor_tx.toString("hex")}` } : {}),
          }
        : null;

      // what `fr agent update-registration` would publish for this agent (a local: agent has no registry)
      const anchor = ANCHOR_CONTRACTS[CHAINS.BASE_SEPOLIA]?.at(
        -1,
      ) as (typeof ANCHOR_CONTRACTS)[number][number];
      const afr: AfrService = {
        name: AFR_SERVICE_NAME,
        endpoint: `https://verify.afr.dev/agents/${agentId}`,
        version: AFR_SERVICE_VERSION,
        afr: {
          agentKey: agentKey(agentId),
          arkiv: {
            chainId: CHAINS.ARKIV_RABDI,
            schemas: ["afr.batch.v1", "afr.checkpoint.v1"],
            writers: [writer],
          },
          anchor: {
            chainId: CHAINS.BASE_SEPOLIA,
            address: anchor.address,
            fromBlock: Number(anchor.fromBlock),
          },
        },
      };
      const verify = await verifyAgent(agentId, {
        store,
        identity: real
          ? rpcIdentityReader(publicClient) // the agent's on-chain registration and operator
          : staticIdentityReader(
              privateKeyToAccount(operatorKey).address.toLowerCase() as Hex,
              afr,
            ),
        anchors: rpcAnchorReader({ [CHAINS.BASE_SEPOLIA]: publicClient }),
        reader,
        writers: [writer],
      });
      report.verify = {
        result: verify.result,
        level: verify.level,
        lanes: verify.lanes,
        findings: verify.findings.map((f) => f.code),
      };

      // CLAUDE.md rule 2: the canary may appear in no attribute or payload of this agent's entities
      let entities = 0;
      let leaks = 0;
      const where = { agent_key: { eq: agentKey(agentId) } } as never;
      for (const s of SCHEMA_NAMES) {
        if (!("agent_key" in SCHEMA_SPEC[s].attrs)) continue;
        for await (const e of store.query({ schema: s, where })) {
          entities++;
          const attrs = JSON.stringify(e.attrs, (_k, x) => (typeof x === "bigint" ? `${x}` : x));
          if (attrs.includes(canary) || Buffer.from(e.payload).toString("latin1").includes(canary))
            leaks++;
        }
      }
      report.plaintext_check = { entities, leaks };

      ok =
        last?.status === "anchored" &&
        verify.result === "PASS" &&
        verify.level === "full" &&
        verify.lanes.length > 0 &&
        verify.lanes.every((l) => l.last_anchor && !l.unanchored_tail) &&
        entities > 0 &&
        leaks === 0;
    } finally {
      reader.priv.fill(0);
      await rec.close();
      await app.close();
    }
    return finish(ok);
  } finally {
    await pool.end();
    if (ok) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
}

main().then(
  (c) => process.exit(c),
  // codes only: messages can carry the keyed RPC URLs
  (e) => {
    process.stderr.write(`testnet-e2e: ${(e as { code?: string }).code ?? "ERROR"}\n`);
    process.exit(1);
  },
);
