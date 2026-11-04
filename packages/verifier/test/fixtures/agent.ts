// Test agent for the verifier: real records, delegations, encrypted frames, keygrants and anchored
// checkpoints in a MemoryStore, built from core/crypto/store only (the verifier may not import the
// recorder). Mirrors the recorder's seal (packages/recorder/src/seal.ts) without commitments or flags.
import { randomBytes } from "node:crypto";
import {
  type AnchorLeaf,
  agentKey,
  anchorProofs,
  anchorRoot,
  type BatchPublicV1,
  batchDigest,
  batchRoot,
  buildBody,
  buildHeader,
  chainRoot,
  DELEGATION_SCOPE,
  hashHeader,
  jcs,
  localSigner,
  type RecordBodyV1,
  type RecordHeaderV1,
  type SyncSigner,
  sortAnchorLeaves,
  typedData,
  ZERO_HASH,
} from "@afr/core";
import { type EpochKek, encryptBatch, newEpochKek, sealKeygrant } from "@afr/crypto";
import {
  encodeBody,
  encodeCanonical,
  encodeFrame,
  MemoryChain,
  MemoryStore,
  type PutRequest,
  packPlaintext,
} from "@afr/store";
import { bytesToHex, concat, type Hex, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type AnchorReader, type IdentityReader, staticIdentityReader } from "../../src/index.js";

// the vectors' agent and session key (private key 0x…01): negative vectors reuse them
export const AGENT_ID = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
export const VECTOR_SK = `0x${"00".repeat(31)}01` as Hex;
export const OPERATOR = privateKeyToAccount(`0x${"0a".repeat(32)}`);
export const ANCHOR_KEY = privateKeyToAccount(`0x${"0b".repeat(32)}`);
export const WRITER = `0x${"a1".repeat(20)}` as Hex;
export const ANCHOR_CHAIN = 31337n;
export const CONTRACT = `0x${"c0".repeat(20)}` as Hex;
export const ANCHOR_CONTRACTS = {
  [Number(ANCHOR_CHAIN)]: [{ address: CONTRACT, fromBlock: 0n, version: 1 }],
};
const IDENTITY_CHAIN = 84532n;
export const T0 = 1_793_577_600n; // 2026-11-02, the vectors' ts (unix s)
const h32 = (s: string) => keccak256(stringToHex(s));
const signers = new Map<Hex, SyncSigner>();
/** localSigner precomputes per key (slow): cached. */
export const signerOf = (k: Hex) => {
  let s = signers.get(k);
  if (!s) {
    s = localSigner(k);
    signers.set(k, s);
  }
  return s;
};

export interface SealedRecord {
  header: RecordHeaderV1;
  headerJcs: string;
  body: RecordBodyV1;
  hash: Hex;
  sig: Hex;
}

export interface FrameRecord {
  seq: bigint;
  hash: Hex;
  sig: Hex;
  headerJcs: string;
  body: Uint8Array;
}

/** In-memory RecorderAnchor: roots by epoch, block time per tx. */
export class FakeAnchors implements AnchorReader {
  readonly roots = new Map<bigint, { root: Hex; tx: Hex; blockTime: bigint }>();
  readonly recorders = new Set<Hex>([ANCHOR_KEY.address.toLowerCase() as Hex]);
  async anchor(_c: bigint, contract: Hex, epoch: bigint, tx: Hex) {
    const a = this.roots.get(epoch);
    if (contract !== CONTRACT || !a) return { root: ZERO_HASH };
    return a.tx === tx ? { root: a.root, blockTime: a.blockTime } : { root: a.root };
  }
  async isRecorder(_c: bigint, _contract: Hex, address: Hex) {
    return this.recorders.has(address.toLowerCase() as Hex);
  }
}

export class Agent {
  readonly chain = new MemoryChain();
  readonly store = new MemoryStore(this.chain, WRITER);
  readonly agentId: string;
  readonly ak: Hex;
  readonly kek: EpochKek;
  readonly identity: IdentityReader;
  readonly anchors = new FakeAnchors();
  /** per lane: next seq, last record hash, chain root */
  readonly tip = new Map<number, { seq: bigint; prevHash: Hex; chainRoot: Hex }>();
  #n = 0;

  constructor(agentId = AGENT_ID) {
    this.agentId = agentId;
    this.ak = agentKey(agentId);
    this.kek = newEpochKek(this.ak, 1, (n) => new Uint8Array(randomBytes(n)));
    this.identity = staticIdentityReader(OPERATOR.address, {
      name: "afr",
      endpoint: "https://verify.afr.test",
      version: "afr/1",
      afr: {
        agentKey: this.ak,
        arkiv: { chainId: 7794095, schemas: ["afr.batch.v1"], writers: [WRITER] },
      },
    });
  }

  async put(req: Omit<PutRequest, "expiresAt" | "idempotencyKey">, store = this.store) {
    return store.await(
      await store.put({
        expiresAt: { days: 30 },
        idempotencyKey: h32(`fixture:${++this.#n}`),
        ...req,
      } as PutRequest),
    );
  }

  async delegate(
    sk: Hex,
    o: { lane?: number; notBefore?: bigint; notAfter?: bigint; by?: typeof OPERATOR } = {},
  ) {
    const message = {
      agentKey: this.ak,
      lane: o.lane ?? 0,
      sessionKey: signerOf(sk).address,
      notBefore: o.notBefore ?? T0 - 60n,
      notAfter: o.notAfter ?? T0 + 86_400n,
      scope: DELEGATION_SCOPE.RECORDS | DELEGATION_SCOPE.KEYGRANTS,
      recorder: "fixture",
      nonce: 7n,
    };
    const sig = await (o.by ?? OPERATOR).signTypedData(
      typedData(IDENTITY_CHAIN, "Delegation", message) as never,
    );
    const json = Object.fromEntries(
      Object.entries(message).map(([k, v]) => [k, typeof v === "bigint" ? v.toString() : v]),
    );
    return this.put({
      schema: "afr.delegation.v1",
      attrs: {
        agent_key: this.ak,
        lane: BigInt(message.lane),
        session_key: message.sessionKey,
        delegator: OPERATOR.address.toLowerCase() as Hex,
        not_before: message.notBefore,
        not_after: message.notAfter,
      },
      payload: encodeCanonical({ message: json, sig }),
      readonly: true,
      lock: true,
      permissionlessExtension: true,
    });
  }

  async profile(writers: Hex[] = [WRITER]) {
    const profile = {
      agentKey: this.ak,
      privacyLevel: 0,
      retentionDays: 30,
      watchedHash: h32("[]"),
      readersHash: h32("[]"),
      version: 1n,
    };
    const sig = await OPERATOR.signTypedData(
      typedData(IDENTITY_CHAIN, "AgentProfile", profile) as never,
    );
    return this.put({
      schema: "afr.agent.v1",
      attrs: {
        agent_key: this.ak,
        agent_id: this.agentId,
        operator: OPERATOR.address.toLowerCase() as Hex,
        privacy: 0n,
        version: 1n,
      },
      payload: encodeCanonical({
        profile: { ...profile, version: "1" },
        sig,
        writers,
        readers: [],
      }),
      readonly: false,
      lock: false,
      permissionlessExtension: true,
    });
  }

  /** `n` records continuing the lane (a session_start first on a fresh lane), signed by `sk`. */
  records(lane: number, n: number, sk: Hex, tsMs = T0 * 1000n): SealedRecord[] {
    const t = this.tip.get(lane) ?? { seq: 0n, prevHash: ZERO_HASH, chainRoot: ZERO_HASH };
    const out: SealedRecord[] = [];
    let { seq, prevHash } = t;
    for (let i = 0; i < n; i++) {
      const salt = h32(`salt:${lane}:${seq}`);
      const { body, commit } = buildBody({ args: { i: Number(seq), note: "fixture" } }, salt);
      const base = {
        agent_id: this.agentId,
        lane,
        session_id: `0x${"12".repeat(16)}`,
        ts: (tsMs + seq).toString(),
      };
      const header =
        seq === 0n
          ? buildHeader(
              {
                ...base,
                type: "session_start",
                commit: {},
                meta: {
                  recorder_version: "fixture",
                  config_hash: h32("config"),
                  delegation_hash: h32("delegation"),
                  session_key: signerOf(sk).address,
                },
              },
              { seq, prevHash },
            )
          : buildHeader({ ...base, type: "note", commit }, { seq, prevHash });
      const hash = hashHeader(header);
      out.push({
        header,
        headerJcs: jcs(header),
        body: seq === 0n ? { salt } : body,
        hash,
        sig: signerOf(sk).signDigest(hash),
      });
      prevHash = hash;
      seq++;
    }
    this.tip.set(lane, { ...t, seq, prevHash });
    return out;
  }

  /** A frame for these records, batch-signed by `batchSk` (default: the records' key). */
  seal(
    lane: number,
    records: FrameRecord[],
    sk: Hex,
    o: { prevChainRoot?: Hex; batchSk?: Hex } = {},
  ): { pub: BatchPublicV1; ct: Uint8Array } {
    const seqFrom = records[0]?.seq ?? 0n;
    const seqTo = records.at(-1)?.seq ?? 0n;
    const prev = o.prevChainRoot ?? this.tip.get(lane)?.chainRoot ?? ZERO_HASH;
    const root = batchRoot(records.map((r) => ({ seq: r.seq, hash: r.hash })));
    const chain = chainRoot(prev, root, seqTo);
    const sealed = encryptBatch(
      packPlaintext(
        { headers: records.map((r) => r.headerJcs), bodies: records.map((r) => r.body) },
        { padding: false },
      ),
      { agentKey: this.ak, lane, seqFrom, seqTo, batchRoot: root },
      this.kek,
      (n) => new Uint8Array(randomBytes(n)),
    );
    const digest = batchDigest({
      agentKey: this.ak,
      lane,
      seqFrom,
      seqTo,
      batchRoot: root,
      prevChainRoot: prev,
      chainRoot: chain,
      payloadCtHash: sealed.payloadCtHash,
    });
    const pub: BatchPublicV1 = {
      v: 1,
      agent_id: this.agentId,
      lane,
      seq_from: seqFrom.toString(),
      seq_to: seqTo.toString(),
      prev_chain_root: prev,
      chain_root: chain,
      batch_root: root,
      session_keys: [signerOf(sk).address.toLowerCase()],
      records: records.map((r) => ({ seq: r.seq.toString(), hash: r.hash, sig: r.sig, sk: 0 })),
      tx_commitments: [],
      nonce_commitments: [],
      epoch_id: this.kek.epochId,
      kek_id: this.kek.kekId,
      wrapped_dek: bytesToHex(sealed.wrappedDek),
      iv: bytesToHex(sealed.iv),
      payload_ct_hash: sealed.payloadCtHash,
      batch_sig: signerOf(o.batchSk ?? sk).signDigest(digest),
    };
    return { pub, ct: sealed.ct };
  }

  async putFrame(f: { pub: BatchPublicV1; ct: Uint8Array }, store = this.store) {
    const p = f.pub;
    return this.put(
      {
        schema: "afr.batch.v1",
        attrs: {
          agent_key: this.ak,
          lane: BigInt(p.lane),
          seq_from: BigInt(p.seq_from),
          seq_to: BigInt(p.seq_to),
          chain_root: p.chain_root as Hex,
          prev_chain_root: p.prev_chain_root as Hex,
          batch_root: p.batch_root as Hex,
          session_key: p.session_keys[0] as Hex,
          epoch_id: BigInt(p.epoch_id),
          record_count: BigInt(p.records.length),
          privacy: 0n,
        },
        payload: encodeFrame(f),
        readonly: true,
        permissionlessExtension: true,
        lock: true,
      },
      store,
    );
  }

  /** `n` fresh records on `lane` → one batch on Arkiv; advances the lane's chain root. */
  async batch(lane: number, n: number, sk: Hex) {
    const recs = this.records(lane, n, sk);
    const f = this.seal(lane, recs.map(frameRecord), sk);
    await this.putFrame(f);
    (this.tip.get(lane) as { chainRoot: Hex }).chainRoot = f.pub.chain_root as Hex;
    return f;
  }

  async grant(readerPub: Hex, sk: Hex) {
    const { enc, ct } = await sealKeygrant(this.kek, readerPub, this.ak);
    const statement = {
      agentKey: this.ak,
      epochId: this.kek.epochId,
      kekId: this.kek.kekId,
      reader: readerPub,
      encHash: keccak256(concat([enc, ct])),
    };
    const sig = await privateKeyToAccount(sk).signTypedData(
      typedData(IDENTITY_CHAIN, "KeyGrant", statement) as never,
    );
    return this.put({
      schema: "afr.keygrant.v1",
      attrs: {
        agent_key: this.ak,
        epoch_id: BigInt(this.kek.epochId),
        reader: readerPub,
        kek_id: this.kek.kekId,
      },
      payload: encodeCanonical({ enc, ct, statement, sig }),
      readonly: true,
      lock: false,
      permissionlessExtension: false,
    });
  }

  /** Anchors the current tip of `lanes` in one epoch and publishes their checkpoints. */
  async anchor(
    lanes: number[],
    o: { blockTime?: bigint; chainRoot?: Hex; by?: typeof ANCHOR_KEY; badProof?: boolean } = {},
  ) {
    const leaves: AnchorLeaf[] = lanes.map((lane) => {
      const t = this.tip.get(lane) as { seq: bigint; chainRoot: Hex };
      return { agentKey: this.ak, lane, seqTo: t.seq - 1n, chainRoot: o.chainRoot ?? t.chainRoot };
    });
    // a second dummy leaf keeps proofs non-empty, so a bad proof is detectable
    const sorted = sortAnchorLeaves([
      ...leaves,
      { agentKey: h32("other agent"), lane: 0, seqTo: 1n, chainRoot: h32("other") },
    ]);
    const root = anchorRoot(sorted);
    const proofs = anchorProofs(sorted);
    const epoch = BigInt(this.anchors.roots.size + 1);
    const tx = h32(`anchor-tx:${epoch}`);
    this.anchors.roots.set(epoch, { root, tx, blockTime: o.blockTime ?? T0 + 600n });
    for (const [i, l] of sorted.entries()) {
      if (l.agentKey !== this.ak) continue;
      const message = {
        agentKey: l.agentKey,
        lane: l.lane,
        seqTo: l.seqTo,
        chainRoot: l.chainRoot,
        anchorRoot: root,
        anchorChainId: ANCHOR_CHAIN,
        anchorTx: tx,
      };
      const sig = await (o.by ?? ANCHOR_KEY).signTypedData(
        typedData(IDENTITY_CHAIN, "CheckpointStatement", message) as never,
      );
      await this.put({
        schema: "afr.checkpoint.v1",
        attrs: {
          agent_key: l.agentKey,
          lane: BigInt(l.lane),
          seq_to: l.seqTo,
          chain_root: l.chainRoot,
          anchor_root: root,
          anchor_tx: tx,
        },
        payload: encodeCanonical({
          statement: {
            ...message,
            seqTo: l.seqTo.toString(),
            anchorChainId: ANCHOR_CHAIN.toString(),
          },
          sig,
          proof: o.badProof ? [h32("wrong")] : proofs[i],
          epoch: epoch.toString(),
          contract: CONTRACT,
        }),
        readonly: true,
        permissionlessExtension: true,
        lock: true,
      });
    }
    return { epoch, root, tx };
  }
}

export const frameRecord = (r: SealedRecord): FrameRecord => ({
  seq: BigInt(r.header.seq),
  hash: r.hash,
  sig: r.sig,
  headerJcs: r.headerJcs,
  body: encodeBody(r.body),
});
