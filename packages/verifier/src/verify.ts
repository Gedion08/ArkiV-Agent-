// verifyAgent (L7 §3 [NORMATIVE for result semantics]): structural verification of an agent's evidence
// over injected readers, plus full mode (decrypt + per-record checks) when a reader key is given.
// Arkiv data is untrusted: forged entities that carry no valid signature are ignored and counted, never
// trusted; a valid chain can only be broken by data signed under a valid delegation.
import {
  AfrError,
  ANCHOR_CONTRACTS,
  type AnchorContract,
  agentKey as agentKeyOf,
  batchDigest,
  batchRoot,
  chainRoot,
  DELEGATION_SCOPE,
  EIP712_TYPES,
  isLocalAgentId,
  LIMITS,
  parseAgentId,
  recoverRecordSigner,
  type StatementType,
  typedData,
  verifyAnchorProof,
  ZERO_HASH,
} from "@afr/core";
import type { EpochKek, ReaderKey } from "@afr/crypto";
import {
  type BatchEntity,
  decodeCanonical,
  decodeFrame,
  type EvidenceStore,
  type Frame,
  groupDuplicates,
  listBatches,
} from "@afr/store";
import { type Hex, keccak256, recoverTypedDataAddress, type TypedDataDefinition } from "viem";
import { epochKek, openBatch } from "./decrypt.js";
import type { AnchorReader, IdentityReader } from "./readers.js";

export const VERIFIER_VERSION = "@afr/verifier@0.1.0"; // keep in step with package.json
/** L1 §7: a record must be anchored before its delegation's notAfter + 1 h. */
const ANCHOR_GRACE_S = 3600n;

export type Severity = "fail" | "warn" | "info";
export type VerifyResult = "PASS" | "PASS_WITH_WARNINGS" | "FAIL";

export interface VerifyFinding {
  code: string;
  severity: Severity;
  lane?: number;
  seq?: string;
  batch?: Hex;
  detail?: string;
}

export interface LaneReport {
  lane: number;
  records: string;
  batches: number;
  seq_range: [string, string] | null;
  last_anchor?: { epoch: string; tx: Hex; block_time?: string; seq_to: string };
  unanchored_tail?: { count: string; oldest_ts?: string };
}

export interface VerifyReport {
  verifier: string;
  format: "afr/1";
  agent_id: string;
  level: "structural" | "full";
  result: VerifyResult;
  checked_at: string;
  lanes: LaneReport[];
  findings: VerifyFinding[];
  attestations: { attestor: Hex; verdict: number; seq_to: string; scope: string }[];
}

export interface VerifyOptions {
  store: EvidenceStore;
  identity: IdentityReader;
  /** Base (anchor chain) reader; without it anchors aren't checked (ANCHOR_NOT_CHECKED, warn). */
  anchors?: AnchorReader;
  /** Only this lane (default: every lane with a valid delegation). */
  lane?: number;
  /** Full mode: open keygrants with this reader key and check every record. */
  reader?: ReaderKey;
  /** Writer allowlist override (default: registration afr.arkiv.writers, then the profile's). */
  writers?: Hex[];
  /** Read every writer's entities (--no-writer-filter). */
  noWriterFilter?: boolean;
  /** Trusted RecorderAnchor deployments (default: @afr/core ANCHOR_CONTRACTS). */
  anchorContracts?: Readonly<Record<number, readonly AnchorContract[]>>;
  now?: () => Date;
}

interface Delegation {
  lane: number;
  scope: number;
  notBefore: bigint;
  notAfter: bigint;
}

interface ValidAnchor {
  seqTo: bigint;
  chainRoot: Hex;
  epoch: bigint;
  tx: Hex;
  blockTime?: bigint;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const lower = (h: unknown) => (typeof h === "string" ? (h.toLowerCase() as Hex) : undefined);
const decode = (payload: Uint8Array): Record<string, unknown> | undefined => {
  try {
    const d = decodeCanonical(payload);
    return isObj(d) ? d : undefined;
  } catch {
    return undefined;
  }
};

/** EIP-712 typed data from a JSON-boundary message (uint fields as decimal strings → bigint). */
function typed(chainId: bigint, type: StatementType, m: Record<string, unknown>) {
  const msg = Object.fromEntries(
    EIP712_TYPES[type].map(({ name, type: t }) => {
      const v = m[name];
      return [name, t.startsWith("uint") && typeof v === "string" ? BigInt(v) : v];
    }),
  );
  return typedData(chainId, type, msg) as unknown as TypedDataDefinition;
}

async function recoverTyped(td: TypedDataDefinition, sig: unknown): Promise<Hex | undefined> {
  if (typeof sig !== "string") return undefined;
  return recoverTypedDataAddress({ ...td, signature: sig as Hex })
    .then((a) => a.toLowerCase() as Hex)
    .catch(() => undefined);
}

const identityChainId = (agentId: string) =>
  isLocalAgentId(agentId) ? 8453n : parseAgentId(agentId).chainId;

export async function verifyAgent(agentId: string, o: VerifyOptions): Promise<VerifyReport> {
  const now = o.now ?? (() => new Date());
  const ak = agentKeyOf(agentId);
  const chainId = identityChainId(agentId);
  const findings: VerifyFinding[] = [];
  const add = (f: VerifyFinding) => findings.push(f);
  const report = (lanes: LaneReport[], attestations: VerifyReport["attestations"] = []) => {
    const result: VerifyResult = findings.some((f) => f.severity === "fail")
      ? "FAIL"
      : findings.some((f) => f.severity === "warn")
        ? "PASS_WITH_WARNINGS"
        : "PASS";
    return {
      verifier: VERIFIER_VERSION,
      format: "afr/1" as const,
      agent_id: agentId,
      level: o.reader ? ("full" as const) : ("structural" as const),
      result,
      checked_at: now().toISOString(),
      lanes,
      findings,
      attestations,
    };
  };

  // 1 identity
  let afr: Awaited<ReturnType<IdentityReader["resolve"]>>["afr"];
  try {
    afr = (await o.identity.resolve(agentId)).afr;
  } catch (e) {
    const code = (e as AfrError).code;
    if (code !== "AGENT_NOT_REGISTERED" && code !== "REGISTRATION_INVALID") throw e; // infra: exit 3
    add({ code: "ID_UNRESOLVED", severity: "fail", detail: code });
    return report([]);
  }
  if (!afr) add({ code: "ID_NO_AFR_SERVICE", severity: "warn" });
  else if (lower(afr.afr.agentKey) !== ak)
    add({ code: "ID_NO_AFR_SERVICE", severity: "warn", detail: "afr.agentKey does not match" });
  const nowS = BigInt(Math.floor(now().getTime() / 1000));
  const opSig = (td: TypedDataDefinition, sig: unknown, ts: bigint) =>
    typeof sig === "string" ? o.identity.isOperatorSig(agentId, td, sig as Hex, ts) : false;

  // latest valid profile: its writers are the discovery filter after the registration's
  let profile: { version: bigint; writers?: Hex[] } | undefined;
  let profiles = 0;
  for await (const e of o.store.query({
    schema: "afr.agent.v1",
    where: { agent_key: { eq: ak } },
  })) {
    profiles++;
    const d = decode(e.payload);
    const p = d?.profile;
    if (!isObj(p) || lower(p.agentKey) !== ak) continue;
    try {
      if (!(await opSig(typed(chainId, "AgentProfile", p), d?.sig, nowS))) continue;
    } catch (err) {
      if (err instanceof AfrError) throw err;
      continue; // malformed message
    }
    const version = BigInt(p.version as string);
    if (profile && profile.version >= version) continue;
    const writers = Array.isArray(d?.writers)
      ? (d.writers.map(lower).filter(Boolean) as Hex[])
      : undefined;
    profile = { version, ...(writers ? { writers } : {}) };
  }
  if (!profile)
    add({
      code: "PROFILE_INVALID",
      severity: "warn",
      detail: profiles ? "no profile signed by the operator" : "no profile",
    });
  let writers =
    o.writers ??
    (afr?.afr.arkiv.writers.length ? afr.afr.arkiv.writers.map(lower) : profile?.writers);
  if (o.noWriterFilter) writers = undefined;
  else if (!writers?.length) {
    add({ code: "NO_WRITER_LIST", severity: "warn", detail: "reading every writer's entities" });
    writers = undefined;
  }
  const createdBy = writers ? { createdBy: writers as Hex[] } : {};

  // 2 delegations and revocations (invalid ones are ignored, with a warning)
  const delegations = new Map<Hex, Delegation[]>();
  for await (const e of o.store.query({
    schema: "afr.delegation.v1",
    where: { agent_key: { eq: ak } },
    ...createdBy,
  })) {
    const d = decode(e.payload);
    const m = d?.message;
    const sk = lower(isObj(m) ? m.sessionKey : undefined);
    let ok = false;
    try {
      ok =
        isObj(m) &&
        sk !== undefined &&
        lower(m.agentKey) === ak &&
        sk === e.attrs.session_key.toLowerCase() &&
        BigInt(m.lane as string) === e.attrs.lane &&
        (await opSig(typed(chainId, "Delegation", m), d?.sig, BigInt(m.notBefore as string)));
    } catch (err) {
      if (err instanceof AfrError) throw err;
    }
    if (!ok || !isObj(m) || !sk) {
      add({ code: "DELEGATION_BAD_SIG", severity: "warn", detail: e.ref.key });
      continue;
    }
    // shortcut: depth-1 only (operator → session key); identity-key sub-delegation (L1 §7.1) lands with that recorder mode
    delegations.set(sk, [
      ...(delegations.get(sk) ?? []),
      {
        lane: Number(m.lane),
        scope: Number(m.scope),
        notBefore: BigInt(m.notBefore as string),
        notAfter: BigInt(m.notAfter as string),
      },
    ]);
  }
  const revokedAt = new Map<Hex, bigint>();
  for await (const e of o.store.query({
    schema: "afr.revocation.v1",
    where: { agent_key: { eq: ak } },
  })) {
    const d = decode(e.payload);
    const m = d?.message;
    const sk = lower(isObj(m) ? m.sessionKey : undefined);
    try {
      if (!isObj(m) || !sk || lower(m.agentKey) !== ak) continue;
      const at = BigInt(m.effectiveAt as string);
      if (!(await opSig(typed(chainId, "Revocation", m), d?.sig, at))) continue;
      const prev = revokedAt.get(sk);
      if (prev === undefined || at < prev) revokedAt.set(sk, at);
    } catch (err) {
      if (err instanceof AfrError) throw err;
    }
  }
  const delegatedFor = (sk: Hex, lane: number) =>
    (delegations.get(sk) ?? []).filter(
      (d) => d.lane === lane && (d.scope & DELEGATION_SCOPE.RECORDS) !== 0,
    );

  const lanes =
    o.lane !== undefined
      ? [o.lane]
      : [...new Set([...delegations.values()].flat().map((d) => d.lane))].sort((a, b) => a - b);
  if (!lanes.length) add({ code: "NO_VALID_DELEGATION", severity: "warn" });
  const laneReports: LaneReport[] = [];
  for (const lane of lanes) laneReports.push(await verifyLane(lane));

  // 5 attestations (informational): signed by the attestor named in the entity
  const attestations: VerifyReport["attestations"] = [];
  for await (const e of o.store.query({
    schema: "afr.attestation.v1",
    where: { agent_key: { eq: ak } },
  })) {
    const d = decode(e.payload);
    const s = d?.statement;
    try {
      if (!isObj(s) || lower(s.agentKey) !== ak) continue;
      if (
        (await recoverTyped(typed(chainId, "Attestation", s), d?.sig)) !== lower(e.attrs.attestor)
      )
        continue;
      attestations.push({
        attestor: lower(e.attrs.attestor) as Hex,
        verdict: Number(s.verdict),
        seq_to: String(s.seqTo),
        scope: String(s.scope),
      });
    } catch {}
  }
  return report(laneReports, attestations);

  async function verifyLane(lane: number): Promise<LaneReport> {
    const at = (b: BatchEntity) => ({ lane, batch: b.ref.key, seq: `${b.attrs.seq_from}` });
    const frames = new Map<Hex, Frame>();
    let ignored = 0;
    // 3 batches. Validity = decodes, matches its attrs and is signed by a delegated session key. From an
    // allowlisted writer an invalid batch is a failure; from anyone else it's noise (V4).
    const { batches, equivocations } = await groupDuplicates(
      listBatches(o.store, {
        agentKey: ak,
        lane: BigInt(lane),
        ...(writers ? { writers: writers as Hex[] } : {}),
      }),
      async (b) => {
        const bad = (code: string) => {
          if (writers) add({ code, severity: "fail", ...at(b) });
          else ignored++;
          return false;
        };
        let f: Frame;
        try {
          f = decodeFrame(b.payload);
        } catch {
          return bad("FRAME_DECODE");
        }
        const p = f.pub;
        if (
          agentKeyOf(p.agent_id) !== ak ||
          p.agent_id !== agentId ||
          BigInt(p.lane) !== b.attrs.lane ||
          BigInt(p.seq_from) !== b.attrs.seq_from ||
          BigInt(p.seq_to) !== b.attrs.seq_to ||
          p.chain_root !== b.attrs.chain_root ||
          p.batch_root !== b.attrs.batch_root
        )
          return bad("ATTR_MISMATCH");
        const signer = await recoverRecordSigner(
          batchDigest({
            agentKey: ak,
            lane: p.lane,
            seqFrom: BigInt(p.seq_from),
            seqTo: BigInt(p.seq_to),
            batchRoot: p.batch_root as Hex,
            prevChainRoot: p.prev_chain_root as Hex,
            chainRoot: p.chain_root as Hex,
            payloadCtHash: p.payload_ct_hash as Hex,
          }),
          p.batch_sig as Hex,
        ).catch(() => undefined);
        const listed = p.session_keys.map((k) => k.toLowerCase());
        if (!signer || !listed.includes(signer) || !delegatedFor(signer, lane).length) {
          ignored++; // IGNORED_UNSIGNED: anyone can write a frame; only delegated keys count
          return false;
        }
        frames.set(b.ref.key, f);
        return true;
      },
    );
    if (ignored)
      add({ code: "IGNORED_UNSIGNED", severity: "info", lane, detail: `${ignored} batches` });
    if (!batches.length) add({ code: "NO_VALID_BATCHES", severity: "warn", lane });
    for (const e of equivocations)
      add({
        code: "EQUIVOCATION",
        severity: "fail",
        lane,
        seq: `${e.seqFrom}`,
        detail: e.keys.join(","),
      });

    let expectSeq = 0n;
    let expectRoot: Hex = ZERO_HASH;
    let prevRecordHash: Hex = ZERO_HASH;
    let records = 0n;
    const rootAt = new Map<bigint, Hex>(); // seq_to → chain root as we computed it
    const keks = new Map<number, EpochKek | null>();
    const tsBySeq = new Map<bigint, bigint>(); // full mode: record ts (ms)
    for (const b of batches) {
      const f = frames.get(b.ref.key) as Frame;
      const p = f.pub;
      const where = at(b);
      const seqFrom = BigInt(p.seq_from);
      const seqTo = BigInt(p.seq_to);
      if (seqFrom !== expectSeq)
        add({ code: "SEQ_GAP", severity: "fail", ...where, detail: `expected ${expectSeq}` });
      else if (p.prev_chain_root !== expectRoot)
        add({ code: "CHAIN_BREAK", severity: "fail", ...where });
      const root = (() => {
        try {
          return batchRoot(p.records.map((r) => ({ seq: BigInt(r.seq), hash: r.hash as Hex })));
        } catch {
          return undefined;
        }
      })();
      if (root !== p.batch_root) add({ code: "MERKLE_MISMATCH", severity: "fail", ...where });
      for (const r of p.records) {
        const signer = await recoverRecordSigner(r.hash as Hex, r.sig as Hex).catch(
          () => undefined,
        );
        if (!signer || signer !== p.session_keys[r.sk]?.toLowerCase())
          add({ code: "RECORD_SIG", severity: "fail", ...where, seq: r.seq });
      }
      // the chain continues from what the batch claims, so one break doesn't cascade
      const chain = chainRoot(p.prev_chain_root as Hex, p.batch_root as Hex, seqTo);
      if (chain !== p.chain_root) add({ code: "CHAIN_ROOT_MISMATCH", severity: "fail", ...where });
      if (keccak256(f.ct) !== p.payload_ct_hash)
        add({ code: "CT_HASH", severity: "fail", ...where });
      if (o.reader) {
        if (!keks.has(p.epoch_id))
          keks.set(
            p.epoch_id,
            await epochKek(
              {
                store: o.store,
                reader: o.reader,
                ...(writers ? { writers: writers as Hex[] } : {}),
              },
              ak,
              f,
              (x) =>
                // no usable grant for this reader: full checks skipped for the epoch; anyone can post a
                // bad grant, so this never fails the structural result
                add({ ...x, lane, severity: "warn" }),
            ),
          );
        const kek = keks.get(p.epoch_id);
        if (kek) {
          const opened = await openBatch(f, b.ref.key, ak, kek, {
            seq: seqFrom,
            prevHash: prevRecordHash,
          });
          for (const x of opened.findings) add({ ...x, lane });
          // untrusted plaintext: an invalid header (already HEADER_INVALID) carries no usable ts
          for (const r of opened.records)
            if (typeof r.header.ts === "string" && /^\d{1,20}$/.test(r.header.ts))
              tsBySeq.set(r.seq, BigInt(r.header.ts));
        }
      }
      prevRecordHash = (p.records.at(-1)?.hash ?? ZERO_HASH) as Hex;
      records += BigInt(p.records.length);
      rootAt.set(seqTo, p.chain_root as Hex);
      expectSeq = seqTo + 1n;
      expectRoot = p.chain_root as Hex;
    }

    // 4 anchors
    const anchors = await verifyCheckpoints(lane, rootAt);
    anchors.sort((a, b) => (a.seqTo < b.seqTo ? -1 : a.seqTo > b.seqTo ? 1 : 0));

    // delegation time bound: the anchor block time of the first checkpoint covering the batch (L7 §3)
    for (const b of batches) {
      const p = (frames.get(b.ref.key) as Frame).pub;
      const seqTo = BigInt(p.seq_to);
      const anchorTime = anchors.find(
        (a) => a.seqTo >= seqTo && a.blockTime !== undefined,
      )?.blockTime;
      const keys = p.session_keys.map((k) => k.toLowerCase() as Hex);
      for (const [i, sk] of keys.entries()) {
        const ds = delegatedFor(sk, lane);
        const revoked = revokedAt.get(sk);
        const recordTimes = p.records
          .filter((r) => r.sk === i)
          .map((r) => tsBySeq.get(BigInt(r.seq)))
          .filter((t): t is bigint => t !== undefined)
          .map((t) => t / 1000n);
        const ok = ds.some(
          (d) =>
            (anchorTime === undefined || anchorTime <= d.notAfter + ANCHOR_GRACE_S) &&
            recordTimes.every((t) => d.notBefore <= t && t <= d.notAfter),
        );
        const revokedBefore =
          revoked !== undefined &&
          (anchorTime !== undefined
            ? revoked <= anchorTime
            : recordTimes.some((t) => t >= revoked));
        if (!ok || revokedBefore)
          add({
            code: "DELEGATION_INVALID",
            severity: "fail",
            ...at(b),
            detail: `${sk}${revokedBefore ? " revoked" : ""}`,
          });
      }
    }

    // unanchored tail
    const last = anchors.at(-1);
    const lastSeq = expectSeq - 1n;
    const tail = lastSeq - (last?.seqTo ?? -1n);
    const lr: LaneReport = {
      lane,
      records: records.toString(),
      batches: batches.length,
      seq_range: batches.length ? ["0", lastSeq.toString()] : null,
      ...(last
        ? {
            last_anchor: {
              epoch: last.epoch.toString(),
              tx: last.tx,
              ...(last.blockTime !== undefined
                ? { block_time: new Date(Number(last.blockTime) * 1000).toISOString() }
                : {}),
              seq_to: last.seqTo.toString(),
            },
          }
        : {}),
    };
    if (batches.length && tail > 0n) {
      const oldest = tsBySeq.get((last?.seqTo ?? -1n) + 1n);
      lr.unanchored_tail = {
        count: tail.toString(),
        ...(oldest !== undefined ? { oldest_ts: new Date(Number(oldest)).toISOString() } : {}),
      };
      const stale =
        oldest !== undefined &&
        now().getTime() - Number(oldest) >
          LIMITS.ANCHOR_LAG_FACTOR * LIMITS.ANCHOR_CADENCE_S * 1000;
      add({
        code: "UNANCHORED_TAIL",
        severity: stale ? "warn" : "info",
        lane,
        detail: `${tail} records after the last anchor`,
      });
    }
    return lr;
  }

  /** Step 4: checkpoint entities proven against RecorderAnchor roots on the anchor chain. */
  async function verifyCheckpoints(lane: number, rootAt: Map<bigint, Hex>): Promise<ValidAnchor[]> {
    const out: ValidAnchor[] = [];
    const registry = o.anchorContracts ?? ANCHOR_CONTRACTS;
    let ignored = 0;
    let seen = 0;
    for await (const e of o.store.query({
      schema: "afr.checkpoint.v1",
      where: { agent_key: { eq: ak }, lane: { eq: BigInt(lane) } },
    })) {
      seen++;
      if (!o.anchors) continue;
      const d = decode(e.payload);
      const s = d?.statement;
      const contract = lower(d?.contract);
      let c: { anchorChainId: bigint; seqTo: bigint; epoch: bigint } | undefined;
      try {
        if (isObj(s) && contract && Array.isArray(d?.proof))
          c = {
            anchorChainId: BigInt(s.anchorChainId as string),
            seqTo: BigInt(s.seqTo as string),
            epoch: BigInt(d.epoch as string),
          };
      } catch {}
      const trusted =
        c && registry[Number(c.anchorChainId)]?.some((x) => x.address.toLowerCase() === contract);
      if (
        !c ||
        !isObj(s) ||
        !trusted ||
        lower(s.agentKey) !== ak ||
        Number(s.lane) !== lane ||
        typeof s.anchorTx !== "string"
      ) {
        ignored++; // not a checkpoint of ours on a known contract
        continue;
      }
      const statement = s as Record<string, unknown> & {
        anchorTx: Hex;
        chainRoot: Hex;
        anchorRoot: Hex;
      };
      const proof = d?.proof as Hex[];
      const info = await o.anchors.anchor(
        c.anchorChainId,
        contract as Hex,
        c.epoch,
        statement.anchorTx,
      );
      const leaf = {
        agentKey: ak,
        lane,
        seqTo: c.seqTo,
        chainRoot: lower(statement.chainRoot) as Hex,
      };
      const proven =
        info.root !== ZERO_HASH &&
        lower(statement.anchorRoot) === info.root.toLowerCase() &&
        verifyAnchorProof(info.root, leaf, proof);
      const signer = await recoverTyped(typed(chainId, "CheckpointStatement", statement), d?.sig);
      const byRecorder =
        signer !== undefined &&
        (await o.anchors.isRecorder(c.anchorChainId, contract as Hex, signer));
      if (!proven) {
        // a bad proof from an allowlisted anchor key is a real failure; from anyone else, noise
        if (byRecorder)
          add({
            code: "ANCHOR_PROOF",
            severity: "fail",
            lane,
            seq: `${c.seqTo}`,
            detail: `epoch ${c.epoch}`,
          });
        else ignored++;
        continue;
      }
      if (!byRecorder)
        add({
          code: "CHECKPOINT_SIG",
          severity: "warn",
          lane,
          seq: `${c.seqTo}`,
          detail: `epoch ${c.epoch}`,
        });
      if (rootAt.get(c.seqTo) !== leaf.chainRoot)
        add({
          code: "ANCHOR_MISMATCH",
          severity: "fail",
          lane,
          seq: `${c.seqTo}`,
          detail: `epoch ${c.epoch}`,
        });
      out.push({
        seqTo: c.seqTo,
        chainRoot: leaf.chainRoot,
        epoch: c.epoch,
        tx: lower(statement.anchorTx) as Hex,
        ...(info.blockTime !== undefined ? { blockTime: info.blockTime } : {}),
      });
    }
    if (!o.anchors && seen)
      add({ code: "ANCHOR_NOT_CHECKED", severity: "warn", lane, detail: "no anchor-chain reader" });
    if (ignored)
      add({ code: "IGNORED_CHECKPOINT", severity: "info", lane, detail: `${ignored} checkpoints` });
    return out;
  }
}
