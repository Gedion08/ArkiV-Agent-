// fr verify agent | prove | agent show | keys reader (L7 §5, P3-10). Read-only: Arkiv through a store with
// a throwaway writer key and a zero spend cap, identity and anchor chains through public RPCs.
// Exit codes (L7 §4): 0 PASS, 1 PASS_WITH_WARNINGS (2 with --strict), 2 FAIL, 3 usage or infra error;
// an RPC outage is never reported as FAIL.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  ANCHOR_CONTRACTS,
  agentKey,
  batchDigest,
  batchProof,
  isLocalAgentId,
  parseAgentId,
  recoverRecordSigner,
} from "@afr/core";
import { exportReaderBackup, generateReaderKey, importReaderBackup } from "@afr/crypto";
import { type IdentityClient, resolveAgent } from "@afr/identity";
import {
  createArkivStore,
  decodeCanonical,
  decodeFrame,
  type EvidenceStore,
  listBatches,
  MemoryWriteJournal,
} from "@afr/store";
import {
  type AnchorReader,
  type IdentityReader,
  rpcAnchorReader,
  rpcIdentityReader,
  staticIdentityReader,
  type VerifyOptions,
  type VerifyReport,
  verifyAgent,
} from "@afr/verifier";
import { createPublicClient, type Hex, http, type PublicClient } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";

export interface NetDeps {
  store?: EvidenceStore;
  identity?: IdentityReader;
  identityRpc?: IdentityClient;
  anchors?: AnchorReader;
  passphrase?: () => Promise<string>;
  /** Tests: fixture anchor deployments and clock. */
  verify?: Pick<VerifyOptions, "anchorContracts" | "now">;
}

export type Out = (s: string) => void;

export class UsageError extends Error {}

/** Typed without echo on a TTY; no TTY and no AFR_READER_PASSPHRASE → NO_PASSPHRASE. */
function hiddenPrompt(label: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) return Promise.reject(new UsageError("NO_PASSPHRASE"));
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
        if (c === "\u0003") return done(() => reject(new UsageError("CANCELLED")));
        if (c === "\u007f") s = s.slice(0, -1);
        else s += c;
      }
    };
    stdin.on("data", onData);
  });
}

export const defaultPassphrase = (env: NodeJS.ProcessEnv) => () =>
  env.AFR_READER_PASSPHRASE
    ? Promise.resolve(env.AFR_READER_PASSPHRASE)
    : hiddenPrompt("reader key passphrase: ");

const CHAINS: Record<number, typeof base | typeof baseSepolia> = {
  [base.id]: base,
  [baseSepolia.id]: baseSepolia,
};
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const json = (v: unknown) =>
  `${JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2)}\n`;
/** Untrusted text (codes, details, URIs) to a terminal: no control characters. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point
const clean = (s: string) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");

const client = (chainId: number, url?: string) => {
  const chain = CHAINS[chainId];
  if (!chain && !url) throw new UsageError(`no default RPC for chain ${chainId}; pass an RPC URL`);
  return createPublicClient({
    ...(chain ? { chain } : {}),
    transport: http(url, { timeout: 30_000, retryCount: 2 }),
  }) as PublicClient;
};

function arkivStore(env: NodeJS.ProcessEnv): EvidenceStore {
  const accessKey = env.ARKIV_ACCESS_KEY;
  if (!accessKey) throw new UsageError("ARKIV_ACCESS_KEY is required to read Arkiv");
  // read-only: a throwaway account and a zero spend cap, so the writer queue can never send
  return createArkivStore({
    accessKey,
    writerKey: generatePrivateKey(),
    journal: new MemoryWriteJournal(),
    spendCapWei: 0n,
  });
}

export interface NetFlags {
  "identity-rpc"?: string;
  "base-rpc"?: string;
  operator?: string;
}

function identityOf(agentId: string, v: NetFlags, deps: NetDeps): IdentityReader {
  if (deps.identity) return deps.identity;
  if (isLocalAgentId(agentId)) {
    // dev agents have no registry: the operator is given
    if (!v.operator || !ADDR.test(v.operator))
      throw new UsageError("a local: agent needs --operator 0x<address>");
    return staticIdentityReader(v.operator.toLowerCase() as Hex);
  }
  return rpcIdentityReader(
    deps.identityRpc ?? client(Number(parseAgentId(agentId).chainId), v["identity-rpc"]),
  );
}

function anchorsOf(v: NetFlags, deps: NetDeps): AnchorReader {
  if (deps.anchors) return deps.anchors;
  const clients: Record<string, PublicClient> = {};
  for (const id of Object.keys(ANCHOR_CONTRACTS)) clients[id] = client(Number(id), v["base-rpc"]);
  return rpcAnchorReader(clients);
}

function agentArg(id: string | undefined): string {
  if (!id) throw new UsageError("missing <agentId>");
  try {
    agentKey(id);
  } catch {
    throw new UsageError("invalid <agentId>");
  }
  return id;
}

function laneArg(s: string | undefined): number | undefined {
  if (s === undefined) return undefined;
  if (!/^\d{1,5}$/.test(s)) throw new UsageError("--lane must be a small integer");
  return Number(s);
}

async function readerKey(file: string, deps: NetDeps) {
  if (!deps.passphrase) throw new UsageError("no passphrase source");
  try {
    return await importReaderBackup(
      JSON.parse(readFileSync(file, "utf8")),
      await deps.passphrase(),
    );
  } catch (e) {
    throw new UsageError(`reader key: ${(e as { code?: string }).code ?? "unreadable"}`);
  }
}

export interface VerifyFlags extends NetFlags {
  lane?: string;
  "reader-key"?: string;
  json?: boolean;
  strict?: boolean;
  "no-writer-filter"?: boolean;
  writer?: string[];
}

export async function verifyCommand(
  agentId: string | undefined,
  v: VerifyFlags,
  env: NodeJS.ProcessEnv,
  deps: NetDeps,
  print: Out,
): Promise<number> {
  const id = agentArg(agentId);
  const lane = laneArg(v.lane);
  const writers = v.writer ?? [];
  if (!writers.every((w) => ADDR.test(w))) throw new UsageError("--writer must be an address");
  const reader = v["reader-key"] ? await readerKey(v["reader-key"], deps) : undefined;
  let report: VerifyReport;
  try {
    report = await verifyAgent(id, {
      store: deps.store ?? arkivStore(env),
      identity: identityOf(id, v, deps),
      anchors: anchorsOf(v, deps),
      ...(lane !== undefined ? { lane } : {}),
      ...(reader ? { reader } : {}),
      ...(writers.length ? { writers: writers.map((w) => w.toLowerCase() as Hex) } : {}),
      ...(v["no-writer-filter"] ? { noWriterFilter: true } : {}),
      ...deps.verify,
    });
  } finally {
    reader?.priv.fill(0);
  }
  print(v.json ? json(report) : human(report));
  if (report.result === "PASS") return 0;
  if (report.result === "PASS_WITH_WARNINGS") return v.strict ? 2 : 1;
  return 2;
}

const MARK = { fail: "✖", warn: "⚠", info: "ℹ" } as const;

function human(r: VerifyReport): string {
  const lines = [`identity      ${clean(r.agent_id)}`];
  for (const l of r.lanes) {
    const range = l.seq_range ? `seq ${l.seq_range[0]}…${l.seq_range[1]}` : "no records";
    lines.push(`lane ${l.lane}        ${l.records} records · ${l.batches} batches · ${range}`);
    if (l.last_anchor)
      lines.push(
        `anchors       last epoch ${l.last_anchor.epoch} · seq_to ${l.last_anchor.seq_to}${
          l.last_anchor.block_time ? ` · ${l.last_anchor.block_time}` : ""
        }`,
      );
    if (l.unanchored_tail) lines.push(`unanchored    ${l.unanchored_tail.count} records`);
  }
  for (const f of r.findings)
    lines.push(
      `${MARK[f.severity]} ${clean(f.code)}${f.lane !== undefined ? ` lane ${f.lane}` : ""}${
        f.seq ? ` seq ${clean(f.seq)}` : ""
      }${f.detail ? `: ${clean(f.detail)}` : ""}`,
    );
  for (const a of r.attestations)
    lines.push(`attestation   ${a.attestor} verdict ${a.verdict} seq_to ${clean(a.seq_to)}`);
  lines.push(
    `RESULT: ${r.result} (${r.level})${
      r.level === "structural" ? "   — run with --reader-key for full verification" : ""
    }`,
  );
  return `${lines.join("\n")}\n`;
}

/**
 * fr prove <agentId> <seq>: the record's hash and signature, its batch's signed public section, the
 * Merkle path to batch_root, and the first checkpoint covering it. Evidence for VER-07, not a verdict:
 * `fr verify agent` checks the delegations and anchors behind it.
 */
export async function proveCommand(
  agentId: string | undefined,
  seqArg: string | undefined,
  v: NetFlags & { lane?: string; out?: string; "no-writer-filter"?: boolean },
  env: NodeJS.ProcessEnv,
  deps: NetDeps,
  print: Out,
): Promise<number> {
  const id = agentArg(agentId);
  if (!seqArg || !/^\d{1,20}$/.test(seqArg)) throw new UsageError("missing or invalid <seq>");
  if (!v.out) throw new UsageError("--out <proof.json> is required");
  if (existsSync(v.out)) throw new UsageError(`refusing to overwrite ${v.out}`);
  const seq = BigInt(seqArg);
  const lane = laneArg(v.lane) ?? 0;
  const ak = agentKey(id);
  const store = deps.store ?? arkivStore(env);
  const afr = v["no-writer-filter"] ? undefined : (await identityOf(id, v, deps).resolve(id)).afr;
  const writers = afr?.afr.arkiv.writers.map((w) => w.toLowerCase() as Hex);
  for await (const b of listBatches(store, {
    agentKey: ak,
    lane: BigInt(lane),
    ...(writers?.length ? { writers } : {}),
  })) {
    if (b.attrs.seq_from > seq || b.attrs.seq_to < seq) continue;
    let f: ReturnType<typeof decodeFrame>;
    try {
      f = decodeFrame(b.payload);
    } catch {
      continue;
    }
    const p = f.pub;
    const record = p.records.find((r) => BigInt(r.seq) === seq);
    const signer = await recoverRecordSigner(
      batchDigest({
        agentKey: ak,
        lane,
        seqFrom: BigInt(p.seq_from),
        seqTo: BigInt(p.seq_to),
        batchRoot: p.batch_root as Hex,
        prevChainRoot: p.prev_chain_root as Hex,
        chainRoot: p.chain_root as Hex,
        payloadCtHash: p.payload_ct_hash as Hex,
      }),
      p.batch_sig as Hex,
    ).catch(() => undefined);
    // the first frame signed by one of its own keys (spam is skipped, not trusted)
    if (!record || !signer || !p.session_keys.map((k) => k.toLowerCase()).includes(signer))
      continue;
    // the lowest checkpoint covering seq; unverified here (fr verify agent proves it against rootOf)
    let checkpoint: unknown;
    let best: bigint | undefined;
    for await (const c of store.query({
      schema: "afr.checkpoint.v1",
      where: { agent_key: { eq: ak }, lane: { eq: BigInt(lane) } },
    })) {
      try {
        const d = decodeCanonical(c.payload) as { statement?: { seqTo?: unknown } };
        const to = d.statement?.seqTo;
        if (typeof to !== "string" || !/^\d{1,20}$/.test(to)) continue;
        const n = BigInt(to);
        if (n >= seq && (best === undefined || n < best)) [best, checkpoint] = [n, d];
      } catch {}
    }
    const proof = {
      format: "afr-proof/1",
      agent_id: id,
      lane,
      seq: seq.toString(),
      record: { hash: record.hash, sig: record.sig, session_key: p.session_keys[record.sk] },
      merkle_proof: batchProof(
        p.records.map((r) => ({ seq: BigInt(r.seq), hash: r.hash as Hex })),
        seq,
      ),
      batch: {
        entity: b.ref.key,
        seq_from: p.seq_from,
        seq_to: p.seq_to,
        prev_chain_root: p.prev_chain_root,
        chain_root: p.chain_root,
        batch_root: p.batch_root,
        payload_ct_hash: p.payload_ct_hash,
        session_keys: p.session_keys,
        batch_sig: p.batch_sig,
      },
      ...(checkpoint ? { checkpoint } : {}),
    };
    writeFileSync(v.out, json(proof), { flag: "wx" });
    print(json({ out: v.out, seq: proof.seq, batch: b.ref.key, anchored: Boolean(checkpoint) }));
    return 0;
  }
  throw new UsageError(`no signed batch holds seq ${seq} on lane ${lane}`);
}

export async function agentShowCommand(
  agentId: string | undefined,
  v: NetFlags & { json?: boolean },
  deps: NetDeps,
  print: Out,
): Promise<number> {
  const id = agentArg(agentId);
  if (isLocalAgentId(id)) throw new UsageError("local: agents have no registry entry");
  const a = await resolveAgent(
    id,
    deps.identityRpc ?? client(Number(parseAgentId(id).chainId), v["identity-rpc"]),
  );
  const out = {
    agent_id: id,
    agent_key: agentKey(id),
    owner: a.owner,
    uri: a.uri,
    ...(a.agentWallet ? { agent_wallet: a.agentWallet } : {}),
    afr: a.afr?.afr ?? null,
  };
  if (v.json) {
    print(json(out));
    return 0;
  }
  const afr = a.afr?.afr;
  print(
    `${[
      `agent     ${clean(id)}`,
      `key       ${out.agent_key}`,
      `operator  ${a.owner}`,
      `uri       ${clean(a.uri)}`,
      ...(a.agentWallet ? [`wallet    ${a.agentWallet}`] : []),
      afr
        ? `afr       writers ${afr.arkiv.writers.join(", ")}${afr.anchor ? ` · anchor ${afr.anchor.address}` : ""}`
        : "afr       (no afr service in the registration)",
    ].join("\n")}\n`,
  );
  return 0;
}

/** fr keys reader new --out FILE | show FILE (the public key needs no passphrase). */
export async function keysReaderCommand(
  sub: string | undefined,
  file: string | undefined,
  v: { out?: string; json?: boolean },
  deps: NetDeps,
  print: Out,
): Promise<number> {
  if (sub === "new") {
    if (!v.out) throw new UsageError("--out <file.afrkey> is required");
    if (existsSync(v.out)) throw new UsageError(`refusing to overwrite ${v.out}`);
    if (!deps.passphrase) throw new UsageError("no passphrase source");
    const pw = await deps.passphrase();
    if (pw.length < 12) throw new UsageError("passphrase must be at least 12 characters");
    const key = await generateReaderKey();
    const backup = await exportReaderBackup(key, pw);
    key.priv.fill(0);
    writeFileSync(v.out, json(backup), { mode: 0o600, flag: "wx" });
    print(json({ reader: backup.x25519_pub, file: v.out }));
    return 0;
  }
  if (sub === "show") {
    if (!file) throw new UsageError("missing <file.afrkey>");
    let pub: unknown;
    try {
      pub = (JSON.parse(readFileSync(file, "utf8")) as { x25519_pub?: unknown }).x25519_pub;
    } catch {
      throw new UsageError("unreadable key file");
    }
    if (typeof pub !== "string" || !/^0x[0-9a-f]{64}$/.test(pub))
      throw new UsageError("not an .afrkey file");
    print(v.json ? json({ reader: pub }) : `${pub}\n`);
    return 0;
  }
  // shortcut: no `import` (raw key → .afrkey) yet; backups come from `new` or the dashboard
  throw new UsageError("fr keys reader new --out FILE | show FILE");
}
