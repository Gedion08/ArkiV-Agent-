// Crash-safe local journal (L2 §4). Every record is durable here before the action proceeds.
import { createCipheriv } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { Worker } from "node:worker_threads";
import { AfrError, type RecordBodyV1, type RecordHeaderV1, ZERO_HASH } from "@afr/core";
import { aesGcmOpen } from "@afr/crypto";
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

  /** One SQLite transaction: the record is either fully journaled or absent. */
  appendRecord(r: AppendInput): void {
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

  close(): void {
    this.#db.close();
    void this.#checkpointer.terminate();
  }
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
