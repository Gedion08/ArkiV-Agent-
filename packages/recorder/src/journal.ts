// Crash-safe local journal (L2 §4). Every record is durable here before the action proceeds.
import { createCipheriv } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { Worker } from "node:worker_threads";
import { AfrError, type RecordBodyV1, type RecordHeaderV1, ZERO_HASH } from "@afr/core";
import { aesGcmOpen, type EpochKek, openAtRest, sealAtRest } from "@afr/crypto";
import type { WriteEntry, WriteJournal } from "@afr/store";
import Database from "better-sqlite3";
import { concat, type Hex, numberToBytes, stringToBytes, toBytes } from "viem";

/** Journal-internal AAD domain (not part of the evidence format): binds a sealed body to its seq + hash. */
const JOURNAL_AAD = "AFR_JOURNAL_V1";

// SQLite's auto-checkpoint runs inside the committing insert (~20 ms every ~220 records, SPIKES S13).
// A second connection in a worker checkpoints instead, so capture() and the event loop never pay for it.
const CHECKPOINTER = `
const { workerData } = require("node:worker_threads");
const db = new (require(workerData.driver))(workerData.path, { fileMustExist: true });
setInterval(() => { try { db.pragma("wal_checkpoint(PASSIVE)"); } catch {} }, workerData.intervalMs);
`;
const CHECKPOINT_MS = 1000;
const SQLITE_DRIVER = createRequire(import.meta.url).resolve("better-sqlite3");

const MIGRATIONS: string[] = [
  // v1 (the meta table is created by migrate() itself, since it holds schema_version)
  `CREATE TABLE session_keys (
     address TEXT PRIMARY KEY, session_id TEXT NOT NULL,
     delegation_json TEXT NOT NULL, delegation_sig TEXT NOT NULL,
     parent_json TEXT, parent_sig TEXT,
     not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
     published_entity TEXT, created_at INTEGER NOT NULL);
   CREATE TABLE records (
     seq INTEGER PRIMARY KEY, type TEXT NOT NULL, header_jcs TEXT NOT NULL, body_ct BLOB NOT NULL,
     hash TEXT NOT NULL UNIQUE, sig TEXT NOT NULL,
     session_key TEXT NOT NULL REFERENCES session_keys(address),
     batch_seq_from INTEGER, created_at INTEGER NOT NULL);
   CREATE TABLE batches (
     seq_from INTEGER PRIMARY KEY, seq_to INTEGER NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('sealed','prepared','submitting','receipt_confirmed','verified','notified','anchored','pruned','failed')),
     frame BLOB NOT NULL, batch_root TEXT NOT NULL, prev_chain_root TEXT NOT NULL, chain_root TEXT NOT NULL,
     predicted_key TEXT, entity_key TEXT, tx_hash TEXT, signed_tx BLOB, writer_nonce INTEGER,
     attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, anchor_tx TEXT, anchored_at INTEGER,
     created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
   CREATE TABLE outbox (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL CHECK (kind IN ('checkpoint','tx_intent','heartbeat','delegation','status')),
     payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
     next_attempt_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
   CREATE TABLE epochs (
     epoch_id INTEGER PRIMARY KEY, kek_id TEXT NOT NULL, kek_sealed BLOB NOT NULL,
     readers_json TEXT NOT NULL, grants_published INTEGER NOT NULL DEFAULT 0,
     created_at INTEGER NOT NULL, rotated_at INTEGER);`,
  // v2 (P2-10): the WriterQueue's durable write journal (L3 §7), one row per write id
  `CREATE TABLE writes (
     id TEXT PRIMARY KEY, state TEXT NOT NULL, predicted_key TEXT, tx_hash TEXT, nonce INTEGER,
     signed BLOB, reason TEXT, updated_at INTEGER NOT NULL);
   ALTER TABLE epochs ADD COLUMN wraps INTEGER NOT NULL DEFAULT 0;
   ALTER TABLE epochs ADD COLUMN granted_json TEXT NOT NULL DEFAULT '[]';`,
];

export interface SessionKeyRow {
  address: Hex;
  sessionId: Hex;
  delegationJson: string;
  delegationSig: Hex | "";
  notBefore: number;
  notAfter: number;
}

export interface AppendInput {
  seq: bigint;
  header: RecordHeaderV1;
  headerJcs: string;
  body: RecordBodyV1;
  hash: Hex;
  sig: Hex;
  sessionKey: Hex;
}

export interface JournalRecord {
  seq: bigint;
  type: string;
  header: RecordHeaderV1;
  headerJcs: string;
  hash: Hex;
  sig: Hex;
  sessionKey: Hex;
}

export interface JournalOptions {
  path: string;
  agentId: string;
  lane: number;
  key: Uint8Array;
  durability?: "normal" | "strict";
  random: (n: number) => Uint8Array;
  now?: () => number;
}

export type BatchState =
  | "sealed"
  | "prepared"
  | "submitting"
  | "receipt_confirmed"
  | "verified"
  | "notified"
  | "anchored"
  | "pruned"
  | "failed";

export interface EpochRow {
  epochId: number;
  kekId: Hex;
  /** Reader X25519 public keys (32-byte lowercase hex). */
  readers: Hex[];
  /** Readers with a confirmed keygrant for this epoch. */
  granted: Hex[];
  grantsPublished: boolean;
  wraps: number;
  rotatedAt?: number;
}

export interface SealedBatchRow {
  seqFrom: bigint;
  seqTo: bigint;
  frame: Uint8Array;
  batchRoot: Hex;
  prevChainRoot: Hex;
  chainRoot: Hex;
}

export interface BatchRow extends SealedBatchRow {
  state: BatchState;
  predictedKey?: Hex;
  entityKey?: Hex;
  txHash?: Hex;
  attempts: number;
  lastError?: string;
}

interface RecordRow {
  seq: number;
  type: string;
  header_jcs: string;
  hash: string;
  sig: string;
  session_key: string;
}

export class Journal {
  readonly path: string;
  readonly #db: Database.Database;
  readonly #key: Uint8Array;
  readonly #random: (n: number) => Uint8Array;
  readonly #now: () => number;
  readonly #insert: Database.Statement;
  readonly #checkpointer: Worker;

  private constructor(opts: JournalOptions, db: Database.Database) {
    this.path = opts.path;
    this.#db = db;
    this.#key = opts.key;
    this.#random = opts.random;
    this.#now = opts.now ?? Date.now;
    this.#insert = db.prepare(
      "INSERT INTO records (seq, type, header_jcs, body_ct, hash, sig, session_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    db.pragma("wal_autocheckpoint = 0");
    this.#checkpointer = new Worker(CHECKPOINTER, {
      eval: true,
      workerData: { driver: SQLITE_DRIVER, path: opts.path, intervalMs: CHECKPOINT_MS },
    });
    this.#checkpointer.unref();
    // a dead checkpointer must not let the WAL grow unbounded: fall back to SQLite's default
    this.#checkpointer.once("exit", () => {
      if (db.open) db.pragma("wal_autocheckpoint = 1000");
    });
  }

  /** Opens (or creates) the journal. Refuses a journal that belongs to another agent or lane. */
  static open(opts: JournalOptions): Journal {
    mkdirSync(dirname(opts.path), { recursive: true, mode: 0o700 });
    const db = new Database(opts.path);
    chmodSync(opts.path, 0o600); // WAL/SHM files inherit the db file's permissions
    db.pragma("journal_mode = WAL");
    db.pragma(`synchronous = ${opts.durability === "strict" ? "FULL" : "NORMAL"}`);
    db.pragma("foreign_keys = ON");
    migrate(db);
    const meta = db.prepare("SELECT v FROM meta WHERE k = ?");
    const agent = meta.get("agent_id") as { v: string } | undefined;
    if (!agent) {
      const put = db.prepare("INSERT INTO meta (k, v) VALUES (?, ?)");
      db.transaction(() => {
        put.run("agent_id", opts.agentId);
        put.run("lane", String(opts.lane));
        put.run("created_at", String((opts.now ?? Date.now)()));
      })();
    } else if (
      agent.v !== opts.agentId ||
      (meta.get("lane") as { v: string }).v !== String(opts.lane)
    ) {
      db.close();
      throw new AfrError(
        "JOURNAL_AGENT_MISMATCH",
        "journal belongs to a different agent or lane; refusing to mix chains",
      );
    }
    return new Journal(opts, db);
  }

  /** Chain tip derived from the records table (the single source of truth). */
  tip(): { nextSeq: bigint; prevHash: Hex; count: number } {
    const last = this.#db
      .prepare("SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1")
      .get() as { seq: number; hash: Hex } | undefined;
    const { n } = this.#db.prepare("SELECT COUNT(*) AS n FROM records").get() as { n: number };
    return last
      ? { nextSeq: BigInt(last.seq) + 1n, prevHash: last.hash, count: n }
      : { nextSeq: 0n, prevHash: ZERO_HASH, count: 0 };
  }

  setDelegationSig(address: Hex, sig: Hex): void {
    this.#db
      .prepare("UPDATE session_keys SET delegation_sig = ? WHERE address = ?")
      .run(sig, address);
  }

  putSessionKey(row: SessionKeyRow): void {
    this.#db
      .prepare(
        `INSERT INTO session_keys (address, session_id, delegation_json, delegation_sig, not_before, not_after, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(address) DO UPDATE SET delegation_sig = excluded.delegation_sig`,
      )
      .run(
        row.address,
        row.sessionId,
        row.delegationJson,
        row.delegationSig,
        row.notBefore,
        row.notAfter,
        this.#now(),
      );
  }

  sessionKey(address: Hex): SessionKeyRow | undefined {
    const r = this.#db.prepare("SELECT * FROM session_keys WHERE address = ?").get(address) as
      | Record<string, string | number>
      | undefined;
    return r
      ? {
          address: r.address as Hex,
          sessionId: r.session_id as Hex,
          delegationJson: r.delegation_json as string,
          delegationSig: r.delegation_sig as Hex,
          notBefore: r.not_before as number,
          notAfter: r.not_after as number,
        }
      : undefined;
  }

  /** One SQLite transaction: the record is either fully journaled or absent. Returns the body's byte size. */
  appendRecord(r: AppendInput): number {
    if (r.seq > BigInt(Number.MAX_SAFE_INTEGER))
      throw new AfrError("SEQ_OVERFLOW", "seq exceeds 2^53");
    const seq = Number(r.seq);
    const iv = this.#random(12);
    const pt = stringToBytes(JSON.stringify(r.body));
    // native AES-256-GCM on the hot path (noble ≈ 9 % of capture CPU); same ct‖tag layout, read back with noble
    const c = createCipheriv("aes-256-gcm", this.#key, iv).setAAD(aad(r.seq, r.hash));
    const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
    this.#insert.run(
      seq,
      r.header.type,
      r.headerJcs,
      Buffer.from(concat([iv, ct])),
      r.hash,
      r.sig,
      r.sessionKey,
      this.#now(),
    );
    return pt.length;
  }

  *iterate(fromSeq = 0n, pageSize = 1000): Generator<JournalRecord> {
    const page = this.#db.prepare(
      "SELECT seq, type, header_jcs, hash, sig, session_key FROM records WHERE seq >= ? ORDER BY seq LIMIT ?",
    );
    let next = Number(fromSeq);
    for (;;) {
      const rows = page.all(next, pageSize) as RecordRow[];
      for (const row of rows) yield toRecord(row);
      if (rows.length < pageSize) return;
      next = (rows.at(-1) as RecordRow).seq + 1;
    }
  }

  /** Records with seq in [fromSeq, toSeq]. */
  range(fromSeq: bigint, toSeq: bigint): JournalRecord[] {
    return (
      this.#db
        .prepare(
          "SELECT seq, type, header_jcs, hash, sig, session_key FROM records WHERE seq BETWEEN ? AND ? ORDER BY seq",
        )
        .all(Number(fromSeq), Number(toSeq)) as RecordRow[]
    ).map(toRecord);
  }

  readBody(seq: bigint): RecordBodyV1 {
    const row = this.#db
      .prepare("SELECT body_ct, hash FROM records WHERE seq = ?")
      .get(Number(seq)) as { body_ct: Buffer; hash: Hex } | undefined;
    if (!row) throw new AfrError("RECORD_NOT_FOUND", `no record at seq ${seq}`);
    const buf = new Uint8Array(row.body_ct);
    const pt = aesGcmOpen(this.#key, buf.subarray(0, 12), buf.subarray(12), aad(seq, row.hash));
    return JSON.parse(new TextDecoder().decode(pt)) as RecordBodyV1;
  }

  // ---------- batches (L2 §4 state machine) ----------

  /** Chain tip of the batch chain: next unbatched seq and the last chain_root. */
  batchTip(): { nextSeq: bigint; chainRoot: Hex } {
    const r = this.#db
      .prepare("SELECT seq_to, chain_root FROM batches ORDER BY seq_from DESC LIMIT 1")
      .get() as { seq_to: number; chain_root: Hex } | undefined;
    return r
      ? { nextSeq: BigInt(r.seq_to) + 1n, chainRoot: r.chain_root }
      : { nextSeq: 0n, chainRoot: ZERO_HASH };
  }

  /** Sealed batches and their records' batch assignment, in one transaction. */
  insertBatches(rows: SealedBatchRow[]): void {
    const ins = this.#db.prepare(
      `INSERT INTO batches (seq_from, seq_to, state, frame, batch_root, prev_chain_root, chain_root, created_at, updated_at)
       VALUES (?, ?, 'sealed', ?, ?, ?, ?, ?, ?)`,
    );
    const assign = this.#db.prepare(
      "UPDATE records SET batch_seq_from = ? WHERE seq BETWEEN ? AND ?",
    );
    const now = this.#now();
    this.#db.transaction(() => {
      for (const b of rows) {
        const [from, to] = [Number(b.seqFrom), Number(b.seqTo)];
        ins.run(
          from,
          to,
          Buffer.from(b.frame),
          b.batchRoot,
          b.prevChainRoot,
          b.chainRoot,
          now,
          now,
        );
        assign.run(from, from, to);
      }
    })();
  }

  /** Lowest batch not yet `verified` (or later), i.e. the next one the uploader must drive. */
  nextUnverifiedBatch(): BatchRow | undefined {
    const r = this.#db
      .prepare(
        "SELECT * FROM batches WHERE state IN ('sealed','prepared','submitting','receipt_confirmed','failed') ORDER BY seq_from LIMIT 1",
      )
      .get() as Record<string, unknown> | undefined;
    return r && toBatch(r);
  }

  batch(seqFrom: bigint): BatchRow | undefined {
    const r = this.#db.prepare("SELECT * FROM batches WHERE seq_from = ?").get(Number(seqFrom)) as
      | Record<string, unknown>
      | undefined;
    return r && toBatch(r);
  }

  batchCounts(): Partial<Record<BatchState, number>> {
    const rows = this.#db
      .prepare("SELECT state, COUNT(*) AS n FROM batches GROUP BY state")
      .all() as {
      state: BatchState;
      n: number;
    }[];
    return Object.fromEntries(rows.map((r) => [r.state, r.n]));
  }

  updateBatch(
    seqFrom: bigint,
    u: { state: BatchState } & Partial<
      Pick<BatchRow, "predictedKey" | "entityKey" | "txHash" | "attempts" | "lastError">
    >,
  ): void {
    this.#db
      .prepare(
        `UPDATE batches SET state = ?, predicted_key = COALESCE(?, predicted_key), entity_key = COALESCE(?, entity_key),
           tx_hash = COALESCE(?, tx_hash), attempts = COALESCE(?, attempts), last_error = ?, updated_at = ? WHERE seq_from = ?`,
      )
      .run(
        u.state,
        u.predictedKey ?? null,
        u.entityKey ?? null,
        u.txHash ?? null,
        u.attempts ?? null,
        u.lastError ?? null,
        this.#now(),
        Number(seqFrom),
      );
  }

  // ---------- epochs (L4 §2, §7.4) ----------

  /** Persists a new epoch; the KEK is sealed under the journal key, bound to its kek_id. */
  putEpoch(kek: EpochKek, readers: Hex[]): void {
    const sealed = sealAtRest(this.#key, kek.key, toBytes(kek.kekId), this.#random);
    this.#db
      .prepare(
        "INSERT INTO epochs (epoch_id, kek_id, kek_sealed, readers_json, grants_published, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        kek.epochId,
        kek.kekId,
        Buffer.from(sealed),
        JSON.stringify(readers),
        readers.length ? 0 : 1,
        this.#now(),
      );
  }

  latestEpoch(): EpochRow | undefined {
    const r = this.#db.prepare("SELECT * FROM epochs ORDER BY epoch_id DESC LIMIT 1").get() as
      | Record<string, unknown>
      | undefined;
    return r && toEpoch(r);
  }

  epoch(epochId: number): EpochRow | undefined {
    const r = this.#db.prepare("SELECT * FROM epochs WHERE epoch_id = ?").get(epochId) as
      | Record<string, unknown>
      | undefined;
    return r && toEpoch(r);
  }

  epochKek(epochId: number): EpochKek {
    const r = this.#db
      .prepare("SELECT kek_id, kek_sealed FROM epochs WHERE epoch_id = ?")
      .get(epochId) as { kek_id: Hex; kek_sealed: Buffer } | undefined;
    if (!r) throw new AfrError("EPOCH_NOT_FOUND", `no epoch ${epochId}`);
    const key = openAtRest(this.#key, new Uint8Array(r.kek_sealed), toBytes(r.kek_id));
    return { epochId, kekId: r.kek_id, key };
  }

  /** Reader set of an epoch; grants_published = every reader has a confirmed keygrant. */
  setEpochReaders(epochId: number, readers: Hex[]): void {
    const e = this.epoch(epochId);
    if (!e) throw new AfrError("EPOCH_NOT_FOUND", `no epoch ${epochId}`);
    const done = readers.every((r) => e.granted.includes(r));
    this.#db
      .prepare("UPDATE epochs SET readers_json = ?, grants_published = ? WHERE epoch_id = ?")
      .run(JSON.stringify(readers), done ? 1 : 0, epochId);
  }

  markReaderGranted(epochId: number, reader: Hex): void {
    const e = this.epoch(epochId);
    if (!e) throw new AfrError("EPOCH_NOT_FOUND", `no epoch ${epochId}`);
    const granted = [...new Set([...e.granted, reader])];
    const done = e.readers.every((r) => granted.includes(r));
    this.#db
      .prepare("UPDATE epochs SET granted_json = ?, grants_published = ? WHERE epoch_id = ?")
      .run(JSON.stringify(granted), done ? 1 : 0, epochId);
  }

  epochsAwaitingGrants(): EpochRow[] {
    return (
      this.#db
        .prepare("SELECT * FROM epochs WHERE grants_published = 0 ORDER BY epoch_id")
        .all() as Record<string, unknown>[]
    ).map(toEpoch);
  }

  markRotated(epochId: number): void {
    this.#db
      .prepare("UPDATE epochs SET rotated_at = ? WHERE epoch_id = ?")
      .run(this.#now(), epochId);
  }

  addWraps(epochId: number, n: number): void {
    this.#db.prepare("UPDATE epochs SET wraps = wraps + ? WHERE epoch_id = ?").run(n, epochId);
  }

  /** Durable WriterQueue journal (L3 §7): each `set` commits with synchronous=FULL (fsync before broadcast). */
  writeJournal(): WriteJournal {
    const db = this.#db;
    const get = db.prepare("SELECT * FROM writes WHERE id = ?");
    const put = db.prepare(
      `INSERT INTO writes (id, state, predicted_key, tx_hash, nonce, signed, reason, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET state = excluded.state, predicted_key = excluded.predicted_key, tx_hash = excluded.tx_hash,
         nonce = excluded.nonce, signed = excluded.signed, reason = excluded.reason, updated_at = excluded.updated_at`,
    );
    const normal = db.pragma("synchronous", { simple: true });
    return {
      get: async (id) => {
        const r = get.get(id) as Record<string, unknown> | undefined;
        if (!r) return undefined;
        return {
          id: r.id as Hex,
          state: r.state as WriteEntry["state"],
          ...(r.predicted_key ? { predictedKey: r.predicted_key as Hex } : {}),
          ...(r.tx_hash ? { txHash: r.tx_hash as Hex } : {}),
          ...(r.nonce !== null ? { nonce: r.nonce as number } : {}),
          ...(r.signed ? { signed: r.signed as Hex } : {}),
          ...(r.reason ? { reason: r.reason as string } : {}),
        };
      },
      set: async (e) => {
        db.pragma("synchronous = FULL");
        try {
          put.run(
            e.id,
            e.state,
            e.predictedKey ?? null,
            e.txHash ?? null,
            e.nonce ?? null,
            e.signed ?? null,
            e.reason ?? null,
            this.#now(),
          );
        } finally {
          db.pragma(`synchronous = ${normal}`);
        }
      },
    };
  }

  close(): void {
    this.#db.close();
    void this.#checkpointer.terminate();
  }
}

function toEpoch(r: Record<string, unknown>): EpochRow {
  return {
    epochId: r.epoch_id as number,
    kekId: r.kek_id as Hex,
    readers: JSON.parse(r.readers_json as string) as Hex[],
    granted: JSON.parse(r.granted_json as string) as Hex[],
    grantsPublished: r.grants_published === 1,
    wraps: r.wraps as number,
    ...(r.rotated_at !== null ? { rotatedAt: r.rotated_at as number } : {}),
  };
}

function toBatch(r: Record<string, unknown>): BatchRow {
  return {
    seqFrom: BigInt(r.seq_from as number),
    seqTo: BigInt(r.seq_to as number),
    state: r.state as BatchState,
    frame: new Uint8Array(r.frame as Buffer),
    batchRoot: r.batch_root as Hex,
    prevChainRoot: r.prev_chain_root as Hex,
    chainRoot: r.chain_root as Hex,
    ...(r.predicted_key ? { predictedKey: r.predicted_key as Hex } : {}),
    ...(r.entity_key ? { entityKey: r.entity_key as Hex } : {}),
    ...(r.tx_hash ? { txHash: r.tx_hash as Hex } : {}),
    attempts: r.attempts as number,
    ...(r.last_error ? { lastError: r.last_error as string } : {}),
  };
}

function aad(seq: bigint, hash: Hex): Uint8Array {
  return concat([stringToBytes(JOURNAL_AAD), numberToBytes(seq, { size: 8 }), toBytes(hash)]);
}

function toRecord(row: RecordRow): JournalRecord {
  return {
    seq: BigInt(row.seq),
    type: row.type,
    header: JSON.parse(row.header_jcs) as RecordHeaderV1,
    headerJcs: row.header_jcs,
    hash: row.hash as Hex,
    sig: row.sig as Hex,
    sessionKey: row.session_key as Hex,
  };
}

function migrate(db: Database.Database): void {
  db.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
  const row = db.prepare("SELECT v FROM meta WHERE k = 'schema_version'").get() as
    | { v: string }
    | undefined;
  let version = row ? Number(row.v) : 0;
  if (version > MIGRATIONS.length) {
    throw new AfrError(
      "JOURNAL_TOO_NEW",
      `journal schema v${version} is newer than this recorder supports`,
    );
  }
  for (; version < MIGRATIONS.length; version++) {
    const sql = MIGRATIONS[version] as string;
    db.transaction(() => {
      db.exec(sql);
      db.prepare(
        "INSERT INTO meta (k, v) VALUES ('schema_version', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
      ).run(String(version + 1));
    })();
  }
}
