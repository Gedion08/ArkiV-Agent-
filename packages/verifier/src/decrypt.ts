// P2-16 decrypt-and-check, the precursor of the L7 verifier: lists an agent's batches on one lane,
// opens each epoch's keygrant with a reader key, decrypts, and checks every hash, root, link and
// signature it can without the identity layer. Not yet checked (full verifier, P3): delegations behind
// the session keys, the agent profile's writers, and anchors.
// Everything read here is untrusted data: decoded, schema-checked and compared, never interpreted.
import {
  agentKey as agentKeyOf,
  batchDigest,
  batchRoot,
  chainRoot,
  type Finding,
  isLocalAgentId,
  parseAgentId,
  type RecordBodyV1,
  type RecordHeaderV1,
  recoverRecordSigner,
  verifyBody,
  verifyRecords,
  verifyTyped,
  ZERO_HASH,
} from "@afr/core";
import { decryptBatch, type EpochKek, openKeygrant, type ReaderKey } from "@afr/crypto";
import {
  decodeBody,
  decodeCanonical,
  decodeFrame,
  type EvidenceStore,
  type Frame,
  groupDuplicates,
  listBatches,
  unpackPlaintext,
} from "@afr/store";
import { concat, type Hex, hexToBytes, keccak256 } from "viem";

export interface DecryptOptions {
  store: EvidenceStore;
  agentKey: Hex;
  lane?: bigint;
  reader: ReaderKey;
  /** Discovery filter (the agent profile's writers); omit to read every writer's entities. */
  writers?: Hex[];
}

export interface DecryptFinding {
  code: string;
  severity: "fail" | "info";
  seq?: string;
  batch?: Hex;
  detail?: string;
}

export interface DecryptedRecord {
  seq: bigint;
  header: RecordHeaderV1;
  /** Plaintext. Absent when the body didn't decode. */
  body?: RecordBodyV1;
}

export interface DecryptReport {
  batches: number;
  records: DecryptedRecord[];
  findings: DecryptFinding[];
  ok: boolean;
}

type Fail = (f: Omit<DecryptFinding, "severity">) => void;

const errCode = (e: unknown) => (e as { code?: string }).code ?? "ERROR";
const coded = (code: string) => Object.assign(new Error(code), { code });

/** batch_sig must be by one of the batch's own session keys (L1 §5.3). */
async function batchSigOk(f: Frame, agentKey: Hex): Promise<boolean> {
  const p = f.pub;
  const digest = batchDigest({
    agentKey,
    lane: p.lane,
    seqFrom: BigInt(p.seq_from),
    seqTo: BigInt(p.seq_to),
    batchRoot: p.batch_root as Hex,
    prevChainRoot: p.prev_chain_root as Hex,
    chainRoot: p.chain_root as Hex,
    payloadCtHash: p.payload_ct_hash as Hex,
  });
  try {
    const signer = await recoverRecordSigner(digest, p.batch_sig as Hex);
    return p.session_keys.map((k) => k.toLowerCase()).includes(signer);
  } catch {
    return false;
  }
}

export async function decryptAgent(o: DecryptOptions): Promise<DecryptReport> {
  const lane = o.lane ?? 0n;
  const agentKey = o.agentKey.toLowerCase() as Hex;
  const findings: DecryptFinding[] = [];
  const records: DecryptedRecord[] = [];
  const fail: Fail = (f) => findings.push({ severity: "fail", ...f });

  // frame + batch_sig decide validity; equivocation is judged among valid batches only (L7 step 3)
  const frames = new Map<Hex, Frame>();
  const { batches, equivocations } = await groupDuplicates(
    listBatches(o.store, { agentKey, lane, ...(o.writers ? { writers: o.writers } : {}) }),
    async (b) => {
      let f: Frame;
      try {
        f = decodeFrame(b.payload);
      } catch (e) {
        fail({ code: errCode(e), batch: b.ref.key, seq: `${b.attrs.seq_from}` });
        return false;
      }
      const p = f.pub;
      const attrsMatch =
        agentKeyOf(p.agent_id) === agentKey &&
        BigInt(p.lane) === b.attrs.lane &&
        BigInt(p.seq_from) === b.attrs.seq_from &&
        BigInt(p.seq_to) === b.attrs.seq_to;
      if (!attrsMatch || !(await batchSigOk(f, agentKey))) {
        fail({
          code: attrsMatch ? "BATCH_SIG" : "ATTRS_MISMATCH",
          batch: b.ref.key,
          seq: p.seq_from,
        });
        return false;
      }
      frames.set(b.ref.key, f);
      return true;
    },
  );
  for (const e of equivocations)
    fail({ code: e.code, seq: `${e.seqFrom}`, detail: e.keys.join(",") });

  const keks = new Map<number, EpochKek | null>();
  let prevChain: Hex = ZERO_HASH;
  let nextSeq = 0n;
  let prevRecordHash: Hex = ZERO_HASH;
  for (const b of batches) {
    const f = frames.get(b.ref.key) as Frame;
    const p = f.pub;
    const at = { batch: b.ref.key, seq: p.seq_from };
    const seqFrom = BigInt(p.seq_from);
    const seqTo = BigInt(p.seq_to);
    const recordStart = { seq: seqFrom, prevHash: prevRecordHash };
    prevRecordHash = (p.records.at(-1)?.hash ?? ZERO_HASH) as Hex;
    if (seqFrom !== nextSeq) fail({ code: "SEQ_GAP", ...at, detail: `expected ${nextSeq}` });
    else if (p.prev_chain_root !== prevChain) fail({ code: "CHAIN_BREAK", ...at });
    if (
      batchRoot(p.records.map((r) => ({ seq: BigInt(r.seq), hash: r.hash as Hex }))) !==
      p.batch_root
    )
      fail({ code: "BATCH_ROOT", ...at });
    if (chainRoot(p.prev_chain_root as Hex, p.batch_root as Hex, seqTo) !== p.chain_root)
      fail({ code: "CHAIN_ROOT", ...at });
    prevChain = p.chain_root as Hex;
    nextSeq = seqTo + 1n;

    if (!keks.has(p.epoch_id)) keks.set(p.epoch_id, await epochKek(o, agentKey, f, fail));
    const kek = keks.get(p.epoch_id);
    if (!kek) continue;
    let headers: string[];
    let bodies: Uint8Array[];
    try {
      ({ headers, bodies } = unpackPlaintext(
        decryptBatch(
          {
            ct: f.ct,
            iv: hexToBytes(p.iv as Hex),
            wrappedDek: hexToBytes(p.wrapped_dek as Hex),
            epochId: p.epoch_id,
            kekId: p.kek_id as Hex,
          },
          { agentKey, lane: p.lane, seqFrom, seqTo, batchRoot: p.batch_root as Hex },
          kek,
        ),
      ));
    } catch (e) {
      fail({ code: errCode(e), ...at });
      continue;
    }
    if (headers.length !== p.records.length) {
      fail({ code: "RECORD_COUNT", ...at });
      continue;
    }
    let parsed: RecordHeaderV1[];
    try {
      parsed = headers.map((h) => JSON.parse(h) as RecordHeaderV1);
    } catch {
      fail({ code: "HEADER_INVALID", ...at });
      continue;
    }
    const seqOf = (i: number) => p.records[i]?.seq ?? p.seq_from;
    const checks: Finding[] = await verifyRecords(
      parsed.map((header, i) => ({
        header,
        sig: p.records[i]?.sig as Hex,
        hash: p.records[i]?.hash as Hex,
      })),
      { start: recordStart, signers: p.session_keys as Hex[] },
    );
    parsed.forEach((header, i) => {
      let body: RecordBodyV1 | undefined;
      try {
        body = decodeBody(bodies[i] as Uint8Array);
        checks.push(...verifyBody(header, body, i));
      } catch (e) {
        fail({ code: errCode(e), ...at, seq: seqOf(i) });
      }
      records.push({ seq: BigInt(seqOf(i)), header, ...(body ? { body } : {}) });
    });
    for (const x of checks)
      findings.push({
        code: x.code,
        severity: x.severity,
        batch: b.ref.key,
        seq: seqOf(x.index),
        ...(x.detail ? { detail: x.detail } : {}),
      });
  }
  return {
    batches: batches.length,
    records,
    findings,
    ok: !findings.some((x) => x.severity === "fail"),
  };
}

/** Opens this reader's keygrant for the batch's epoch; null (with a finding) when none is usable. */
async function epochKek(
  o: DecryptOptions,
  agentKey: Hex,
  f: Frame,
  fail: Fail,
): Promise<EpochKek | null> {
  const p = f.pub;
  const reader = o.reader.pub.toLowerCase() as Hex;
  const at = { seq: p.seq_from, detail: `epoch ${p.epoch_id}` };
  const chainId = isLocalAgentId(p.agent_id) ? 8453n : parseAgentId(p.agent_id).chainId;
  let seen = false;
  for await (const g of o.store.query({
    schema: "afr.keygrant.v1",
    where: {
      agent_key: { eq: agentKey },
      epoch_id: { eq: BigInt(p.epoch_id) },
      reader: { eq: reader },
    },
    ...(o.writers ? { createdBy: o.writers } : {}),
  })) {
    seen = true;
    try {
      const d = decodeCanonical(g.payload) as {
        enc: Uint8Array;
        ct: Uint8Array;
        statement: { agentKey: Hex; epochId: number; kekId: Hex; reader: Hex; encHash: Hex };
        sig: Hex;
      };
      const s = d?.statement;
      if (
        !(d?.enc instanceof Uint8Array) ||
        !(d.ct instanceof Uint8Array) ||
        s?.agentKey !== agentKey ||
        s.epochId !== p.epoch_id ||
        s.reader !== reader ||
        s.kekId !== p.kek_id ||
        s.encHash !== keccak256(concat([d.enc, d.ct]))
      )
        throw coded("KEYGRANT_INVALID");
      // signed by a session key of the batches it unlocks (their delegations: full verifier)
      let signed = false;
      for (const sk of p.session_keys)
        signed ||= await verifyTyped(chainId, "KeyGrant", s, d.sig, sk as Hex);
      if (!signed) throw coded("KEYGRANT_SIG");
      return await openKeygrant(
        { enc: d.enc, ct: d.ct, epochId: p.epoch_id, kekId: p.kek_id as Hex },
        o.reader.priv,
        agentKey,
      );
    } catch (e) {
      fail({ code: errCode(e), ...at });
    }
  }
  if (!seen) fail({ code: "NO_KEYGRANT", ...at });
  return null;
}
