// Recorder: sequencer + sealing + journal (L2 §2.1, §3, §7.2).
import { randomBytes } from "node:crypto";
import {
  AfrError,
  type ApprovalInfo,
  agentKey,
  type BodyParts,
  buildBody,
  buildHeader,
  hashHeader,
  jcs,
  LIMITS,
  type ModelInfo,
  type PolicyInfo,
  type RecordBodyV1,
  type RecordHeaderV1,
  type SyncSigner,
  type ToolInfo,
  verifyLinks,
} from "@afr/core";
import type { Logger } from "@afr/log";
import type { EvidenceStore } from "@afr/store";
import type { Hex } from "viem";
import { Batcher } from "./batcher.js";
import { type Config, configHash, expandHome } from "./config.js";
import { EpochManager, type KeygrantSealer, publishKeygrants } from "./epochs.js";
import { Journal } from "./journal.js";
import { KeyManager, type SessionKey, type SignatureRequester } from "./keys.js";
import { loadJournalKey } from "./keystore.js";
import { hashBinaryContent, normalizeMeta, normalizeTx, type TxInput } from "./normalize.js";
import { Uploader } from "./uploader.js";

export const RECORDER_VERSION = "afr-recorder/0.1.0";
const ROTATE_BEFORE_S = 600n;
const VERIFY_TAIL = 100n;

export interface CaptureEvent {
  type: RecordHeaderV1["type"];
  at?: number;
  refSeq?: bigint;
  model?: ModelInfo;
  tool?: ToolInfo;
  tx?: TxInput;
  policy?: PolicyInfo;
  approval?: ApprovalInfo;
  meta?: Record<string, string>;
  body?: Omit<BodyParts, "redacted">;
}

export interface SealedRecord {
  seq: bigint;
  header: RecordHeaderV1;
  body: RecordBodyV1;
  hash: Hex;
  sig: Hex;
  sessionKey: Hex;
}

/** `record` is absent when the journal failed in fail-open mode: the seq is reserved for a later gap record. */
export interface CaptureResult {
  seq: bigint;
  record?: SealedRecord;
}

export interface RecorderStatus {
  agentId: string;
  lane: number;
  nextSeq: bigint;
  sessionKey: Hex;
  sessionNotAfter: bigint;
  delegation: "pending" | "signed" | "failed";
  pendingGap?: { from: bigint; to: bigint };
  journalPath: string;
  /** Batch counts by L2 §4 state (when uploading). */
  batches?: ReturnType<Journal["batchCounts"]>;
}

/** Batching + upload (L2 §9). Without it the recorder only journals (P1 behaviour). */
export interface UploadOptions {
  store: EvidenceStore;
  /** L4 §5 HPKE sealer; required once `encryption.readers` is non-empty (uploads wait without it). */
  sealKeygrant?: KeygrantSealer;
  watchKey?: Uint8Array;
  approvalThresholdCents?: bigint;
  /** Extra submission gate (delegations first, P2-12); the keygrant gate always applies. */
  canSubmit?: (sessionKeys: Hex[]) => boolean | Promise<boolean>;
  /** Timer period for age/heartbeat checks (default 1 s). */
  tickMs?: number;
}

export interface RecorderOptions {
  config: Config;
  logger?: Logger;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  random?: (n: number) => Uint8Array;
  requestSignature?: SignatureRequester;
  /** Disable the automatic rotation timer (tests call rotate()). */
  autoRotate?: boolean;
  upload?: UploadOptions;
}

export function laneDir(config: Config): string {
  return `${expandHome(config.data_dir)}/${agentKey(config.agent.id).slice(2, 14)}/lane-${config.agent.lane}`;
}

export class Recorder {
  readonly agentId: string;
  readonly lane: number;
  readonly journal: Journal;
  readonly #cfg: Config;
  readonly #log: Logger | undefined;
  readonly #now: () => number;
  readonly #random: (n: number) => Uint8Array;
  readonly #keys: KeyManager;
  #session!: SessionKey;
  #delegationState: RecorderStatus["delegation"] = "pending";
  #nextSeq: bigint;
  #prevHash: Hex;
  #gap: { from: bigint; to: bigint } | undefined;
  #rotateTimer: NodeJS.Timeout | undefined;
  #closed = false;
  /** Signers of every session opened by this process (batch_sig needs the last record's key). */
  readonly #signers = new Map<Hex, SyncSigner>();
  #batcher: Batcher | undefined;
  #epochs: EpochManager | undefined;
  #upload: UploadOptions | undefined;
  #grantErrorLogged = false;
  #uploader: Uploader | undefined;
  #tick: NodeJS.Timeout | undefined;
  #flushing: Promise<void> | undefined;
  #flushQueued = false;
  #forceQueued = false;
  #lastCaptureAt = 0;
  /** Delegation promises not yet persisted; close() waits for them briefly. */
  readonly #pendingDelegations = new Set<Promise<unknown>>();

  private constructor(o: RecorderOptions, journal: Journal, keys: KeyManager) {
    this.#cfg = o.config;
    this.agentId = o.config.agent.id;
    this.lane = o.config.agent.lane;
    this.#log = o.logger;
    this.#now = o.now ?? Date.now;
    this.#random = o.random ?? ((n) => new Uint8Array(randomBytes(n)));
    this.journal = journal;
    this.#keys = keys;
    const tip = journal.tip();
    this.#nextSeq = tip.nextSeq;
    this.#prevHash = tip.prevHash;
  }

  /** Startup sequence (L2 §7.2 steps 1–3, 6–7). Batching/upload (steps 4, 5, 8) arrive in P2. */
  static async start(o: RecorderOptions): Promise<Recorder> {
    const { config } = o;
    const env = o.env ?? process.env;
    const random = o.random ?? ((n: number) => new Uint8Array(randomBytes(n)));
    const dir = laneDir(config);
    const journal = Journal.open({
      path: `${dir}/journal.sqlite`,
      agentId: config.agent.id,
      lane: config.agent.lane,
      key: loadJournalKey(config.keystore, `${dir}/journal.key`, o.logger),
      durability: config.durability,
      random,
      ...(o.now ? { now: o.now } : {}),
    });
    try {
      const keys = new KeyManager({
        agentId: config.agent.id,
        lane: config.agent.lane,
        delegation: config.delegation,
        recorderVersion: RECORDER_VERSION,
        random,
        ...(o.now ? { now: o.now } : {}),
        ...(env.AFR_OPERATOR_KEY ? { operatorKey: env.AFR_OPERATOR_KEY as Hex } : {}),
        ...(o.requestSignature ? { requestSignature: o.requestSignature } : {}),
      });
      const rec = new Recorder({ ...o, random }, journal, keys);
      const recoveredFrom = rec.#verifyTail();
      if (o.upload) rec.#startUpload(o.upload, random);
      rec.#openSession(
        recoveredFrom === undefined ? {} : { recovered_from_seq: recoveredFrom.toString() },
      );
      if (o.autoRotate !== false) rec.#scheduleRotation();
      return rec;
    } catch (e) {
      journal.close();
      throw e;
    }
  }

  /** Verifies the last 100 journaled records chain to the tip. Returns the tip seq if the journal is non-empty. */
  #verifyTail(): bigint | undefined {
    if (this.#nextSeq === 0n) return undefined;
    const to = this.#nextSeq - 1n;
    const from = to >= VERIFY_TAIL ? to - VERIFY_TAIL + 1n : 0n;
    const recs = this.journal.range(from, to);
    const start = from === 0n ? undefined : this.journal.range(from - 1n, from - 1n)[0];
    const { findings, hashes } = verifyLinks(
      recs.map((r) => r.header),
      start ? { seq: from, prevHash: start.hash } : undefined,
    );
    const fails = findings.filter((f) => f.severity === "fail");
    if (fails.length || recs.some((r, i) => hashes[i] !== r.hash)) {
      throw new AfrError(
        "JOURNAL_CORRUPT",
        `journal tail failed verification (${fails[0]?.code ?? "HEADER_HASH"})`,
      );
    }
    return to;
  }

  #startUpload(u: UploadOptions, random: (n: number) => Uint8Array): void {
    const cfg = this.#cfg;
    const privacy = cfg.agent.privacy_level;
    const key = agentKey(this.agentId);
    const epochs = new EpochManager({
      journal: this.journal,
      agentKey: key,
      readers: cfg.encryption.readers,
      now: this.#now,
      random,
      ...(this.#log ? { logger: this.#log } : {}),
    });
    this.#epochs = epochs;
    this.#upload = u;
    this.#batcher = new Batcher({
      journal: this.journal,
      seal: {
        agentId: this.agentId,
        agentKey: key,
        lane: this.lane,
        privacy,
        padding: cfg.batch?.padding ?? true,
        kek: () => epochs.current(),
        ...(u.watchKey ? { watchKey: u.watchKey } : {}),
        ...(u.approvalThresholdCents !== undefined
          ? { approvalThresholdCents: u.approvalThresholdCents }
          : {}),
        signerFor: (a) => this.#signers.get(a.toLowerCase() as Hex),
        random,
      },
      ...(cfg.batch ? { maxAgeMs: cfg.batch.max_age_ms, targetBytes: cfg.batch.target_bytes } : {}),
      now: this.#now,
      ...(this.#log ? { logger: this.#log } : {}),
    });
    this.#uploader = new Uploader({
      journal: this.journal,
      store: u.store,
      agentKey: key,
      lane: this.lane,
      privacy,
      // ADR-013 amendment: rolling creates live 30 d (extended later); upfront only for ≤ 30 d retention
      expiresAt: { days: Math.min(cfg.agent.retention_days, 30) },
      canSubmit: async (pub) =>
        epochs.grantsReady(pub.epoch_id) &&
        (u.canSubmit ? await u.canSubmit(pub.session_keys as Hex[]) : true),
      ...(this.#log ? { logger: this.#log } : {}),
    });
    this.#lastCaptureAt = this.#now();
    this.#tick = setInterval(() => this.#onTick(), u.tickMs ?? 1000);
    this.#tick.unref();
  }

  #onTick(): void {
    if (this.#closed || !this.#batcher) return;
    const hb = this.#cfg.batch;
    if (
      this.#cfg.agent.privacy_level === 0 &&
      (hb?.heartbeat ?? true) &&
      this.#now() - this.#lastCaptureAt >= (hb?.heartbeat_ms ?? LIMITS.HEARTBEAT_MS)
    ) {
      // heartbeats are ordinary one-record batches (L3 §8), closed right away
      try {
        this.capture({ type: "note", meta: { event: "heartbeat" }, body: { args: {} } });
      } catch {
        return; // fail-closed journal error: nothing to batch
      }
      this.#queueFlush(true);
    } else {
      // shortcut: waiting uploads are retried every tick without backoff; add exponential backoff
      // if a store's rate limits make once-per-second retries costly.
      this.#queueFlush(false);
    }
  }

  /** Never on the capture path: sealing runs on a later macrotask. */
  #queueFlush(force: boolean): void {
    if (this.#closed) return;
    this.#forceQueued ||= force;
    if (this.#flushQueued) return;
    this.#flushQueued = true;
    setImmediate(() => {
      const f = this.#forceQueued;
      this.#flushQueued = false;
      this.#forceQueued = false;
      void this.flush(f);
    });
  }

  /** Seals what is due (or everything, `force`) and drives uploads until idle or blocked. */
  async flush(force = true): Promise<void> {
    if (!this.#batcher || !this.#uploader) return;
    // a forced flush must not be absorbed by a concurrent unforced one: wait, then run its own
    for (let f = this.#flushing; f; f = this.#flushing) {
      await f;
      if (!force) return;
    }
    const batcher = this.#batcher;
    const uploader = this.#uploader;
    this.#flushing = (async () => {
      try {
        if (force || batcher.due()) {
          const wraps = new Map<number, number>();
          for (const b of batcher.seal())
            wraps.set(b.pub.epoch_id, (wraps.get(b.pub.epoch_id) ?? 0) + 1);
          // a crash between sealing and this count under-counts a few wraps: WRAP_MARGIN covers it
          for (const [id, n] of wraps) this.#epochs?.noteWraps(id, n);
        }
        await this.#publishGrants();
        await uploader.drain();
      } catch (e) {
        this.#log?.error(
          { code: (e as { code?: string }).code ?? "BATCH_ERROR" },
          "batch flush failed",
        );
      }
    })().finally(() => {
      this.#flushing = undefined;
    });
    return this.#flushing;
  }

  async #publishGrants(): Promise<void> {
    const u = this.#upload;
    if (!u) return;
    try {
      await publishKeygrants({
        journal: this.journal,
        store: u.store,
        agentKey: agentKey(this.agentId),
        session: this.#session,
        ...(u.sealKeygrant ? { sealKeygrant: u.sealKeygrant } : {}),
        expiresAt: { days: Math.min(this.#cfg.agent.retention_days, 30) },
      });
      this.#grantErrorLogged = false;
    } catch (e) {
      // batches of that epoch wait (gate); log once per outage, not every tick
      if (!this.#grantErrorLogged)
        this.#log?.warn(
          { code: (e as { code?: string }).code ?? "KEYGRANT_ERROR" },
          "keygrants not published; uploads wait",
        );
      this.#grantErrorLogged = true;
    }
  }

  /** L4 §7.4 manual rotation (`fr keys rotate-epoch`): already-sealed batches keep their epoch. */
  rotateEpoch(): void {
    this.#epochs?.rotate("MANUAL");
  }

  /** L4 §7.1/§7.3 reader sync (API `sync_readers`): removal rotates, addition grants the current epoch. */
  setReaders(readers: readonly string[]): void {
    this.#epochs?.setReaders(readers);
  }

  #openSession(extraMeta: Record<string, string>): void {
    const s = this.#keys.newSession();
    this.#session = s;
    this.#signers.set(s.address.toLowerCase() as Hex, s.signer);
    this.#delegationState = "pending";
    this.journal.putSessionKey({
      address: s.address,
      sessionId: s.sessionId,
      delegationJson: jcs(toJson(s.delegation)),
      delegationSig: "",
      notBefore: Number(s.delegation.notBefore),
      notAfter: Number(s.delegation.notAfter),
    });
    const persisted = s.delegationSig.then(
      ({ sig }) => {
        if (this.#closed) return;
        this.journal.setDelegationSig(s.address, sig);
        if (this.#session === s) this.#delegationState = "signed";
      },
      (e: AfrError) => {
        if (this.#session === s) this.#delegationState = "failed";
        this.#log?.error(
          { code: e.code },
          "delegation failed; records stay signed but unpublishable",
        );
      },
    );
    this.#pendingDelegations.add(persisted);
    persisted.finally(() => this.#pendingDelegations.delete(persisted));
    this.capture({
      type: "session_start",
      meta: {
        recorder_version: RECORDER_VERSION,
        config_hash: configHash(this.#cfg),
        delegation_hash: s.delegationHash,
        session_key: s.address,
        ...extraMeta,
      },
    });
  }

  #scheduleRotation(): void {
    const at = (this.#session.delegation.notAfter - ROTATE_BEFORE_S) * 1000n - BigInt(this.#now());
    this.#rotateTimer = setTimeout(
      () => {
        this.rotate().catch((e: AfrError) =>
          this.#log?.error({ code: e.code }, "session rotation failed"),
        );
      },
      Number(at > 0n ? at : 0n),
    );
    this.#rotateTimer.unref();
  }

  /** New session key: session_end{rotate} with the old key, session_start with the new one. Chain continues. */
  async rotate(): Promise<void> {
    if (this.#closed) return;
    clearTimeout(this.#rotateTimer);
    this.capture({ type: "session_end", meta: { reason: "rotate" } });
    this.#openSession({});
    if (this.#rotateTimer) this.#scheduleRotation();
  }

  /**
   * Seals and journals one record, synchronously. Fail-open: a journal failure reserves the seq and
   * returns without a record; the next successful capture first writes a `gap` record. Fail-closed: throws.
   */
  capture(ev: CaptureEvent): CaptureResult {
    if (this.#closed) throw new AfrError("RECORDER_CLOSED", "recorder is closed");
    if (this.#gap && !this.#flushGap()) return this.#reserve();
    try {
      return { seq: this.#nextSeq, record: this.#seal(ev, this.#nextSeq) };
    } catch (e) {
      if (!isJournalError(e) || this.#cfg.fail_mode === "closed") throw e;
      this.#log?.error(
        { code: (e as { code?: string }).code ?? "JOURNAL_WRITE" },
        "journal write failed; reserving seq (fail-open)",
      );
      return this.#reserve();
    }
  }

  #reserve(): CaptureResult {
    const seq = this.#nextSeq++;
    this.#gap = { from: this.#gap?.from ?? seq, to: seq };
    return { seq };
  }

  /** Tries to journal the pending gap record. */
  #flushGap(): boolean {
    const gap = this.#gap as { from: bigint; to: bigint };
    try {
      this.#seal(
        {
          type: "gap",
          meta: {
            from_seq: gap.from.toString(),
            to_seq: gap.to.toString(),
            reason: "journal_write_failed",
          },
        },
        gap.to + 1n,
      );
      this.#gap = undefined;
      return true;
    } catch (e) {
      if (!isJournalError(e)) throw e;
      return false;
    }
  }

  #seal(ev: CaptureEvent, seq: bigint): SealedRecord {
    const s = this.#session;
    const parts: BodyParts = { ...ev.body };
    if (parts.result !== undefined && this.#cfg.capture.binary === "hash")
      parts.result = hashBinaryContent(parts.result);
    // TxInfo.data_commit is required whenever tx is present: no calldata commits to "0x"
    if (ev.tx && parts.calldata === undefined) parts.calldata = "0x";
    const { body, commit } = buildBody(parts, bytesHex(this.#random(32)), {
      maxBytes: this.#cfg.capture.max_body_bytes,
    });
    const tx = ev.tx
      ? { ...normalizeTx(ev.tx), data_commit: commit.calldata as string }
      : undefined;
    const meta = normalizeMeta(ev.meta);
    const header = buildHeader(
      {
        agent_id: this.agentId,
        lane: this.lane,
        session_id: s.sessionId,
        ts: String(ev.at ?? this.#now()),
        type: ev.type,
        commit,
        ...(ev.refSeq !== undefined ? { ref_seq: ev.refSeq.toString() } : {}),
        ...(ev.model ? { model: ev.model } : {}),
        ...(ev.tool ? { tool: ev.tool } : {}),
        ...(tx ? { tx } : {}),
        ...(ev.policy ? { policy: ev.policy } : {}),
        ...(ev.approval ? { approval: ev.approval } : {}),
        ...(meta ? { meta } : {}),
      },
      { seq, prevHash: this.#prevHash },
    );
    const headerJcs = jcs(header);
    const hash = hashHeader(header);
    const sig = s.signer.signDigest(hash);
    const bodyBytes = this.journal.appendRecord({
      seq,
      header,
      headerJcs,
      body,
      hash,
      sig,
      sessionKey: s.address,
    });
    this.#nextSeq = seq + 1n;
    this.#prevHash = hash;
    this.#lastCaptureAt = this.#now();
    if (this.#batcher?.noteRecord(headerJcs.length, bodyBytes)) this.#queueFlush(false);
    return { seq, header, body, hash, sig, sessionKey: s.address };
  }

  status(): RecorderStatus {
    return {
      agentId: this.agentId,
      lane: this.lane,
      nextSeq: this.#nextSeq,
      sessionKey: this.#session.address,
      sessionNotAfter: this.#session.delegation.notAfter,
      delegation: this.#delegationState,
      ...(this.#gap ? { pendingGap: { ...this.#gap } } : {}),
      journalPath: this.journal.path,
      ...(this.#batcher ? { batches: this.journal.batchCounts() } : {}),
    };
  }

  /** Resolves once the current session's delegation is signed (or rejects if it failed). */
  async delegationReady(): Promise<void> {
    await this.#session.delegationSig;
  }

  async close(reason = "shutdown"): Promise<void> {
    if (this.#closed) return;
    clearTimeout(this.#rotateTimer);
    // let in-flight delegation signatures reach the journal (bounded: interactive ones may never arrive)
    await Promise.race([
      Promise.allSettled([...this.#pendingDelegations]),
      new Promise((r) => setTimeout(r, 2000).unref()),
    ]);
    clearInterval(this.#tick);
    try {
      this.capture({ type: "session_end", meta: { reason } });
      // seal everything (the session key is still held) and give uploads a bounded chance
      await Promise.race([this.flush(), new Promise((r) => setTimeout(r, 5000).unref())]);
    } finally {
      this.#closed = true;
      await Promise.race([this.#flushing, new Promise((r) => setTimeout(r, 1000).unref())]);
      this.journal.close();
    }
  }
}

function isJournalError(e: unknown): boolean {
  // better-sqlite3 throws SqliteError (code SQLITE_*); disk-full surfaces as SQLITE_FULL / SQLITE_IOERR
  const code = (e as { code?: unknown })?.code;
  return typeof code === "string" && (code.startsWith("SQLITE_") || code === "JOURNAL_WRITE");
}

function bytesHex(b: Uint8Array): Hex {
  return `0x${Buffer.from(b).toString("hex")}`;
}

function toJson(v: unknown): unknown {
  return JSON.parse(JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x)));
}
