import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildBody, buildHeader, hashHeader, jcs, localSigner, ZERO_HASH } from "@afr/core";
import { createCanary } from "@afr/log";
import { describe, expect, test } from "vitest";
import { Journal } from "../src/journal.js";
import { AGENT } from "./fixtures/setup.js";

const key = new Uint8Array(32).fill(9);
const random = (n: number) => new Uint8Array(randomBytes(n));
const open = (path: string, over = {}) =>
  Journal.open({ path, agentId: AGENT, lane: 0, key, random, ...over });
const signer = localSigner(`0x${"00".repeat(31)}01`);
const SESSION = `0x${"cd".repeat(16)}` as const;

function append(j: Journal, seq: bigint, prev: `0x${string}`, args: unknown) {
  const { body, commit } = buildBody({ args }, `0x${"11".repeat(32)}`);
  const header = buildHeader(
    { agent_id: AGENT, lane: 0, session_id: SESSION, ts: "1", type: "note", commit },
    { seq, prevHash: prev },
  );
  const hash = hashHeader(header);
  j.appendRecord({
    seq,
    header,
    headerJcs: jcs(header),
    body,
    hash,
    sig: signer.signDigest(hash),
    sessionKey: signer.address,
  });
  return hash;
}

describe("P1-11 journal", () => {
  test("creates schema with WAL, 0600 file, and survives reopen", () => {
    const path = join(mkdtempSync(join(tmpdir(), "afr-j-")), "lane-0", "journal.sqlite");
    const j = open(path);
    j.putSessionKey({
      address: signer.address,
      sessionId: SESSION,
      delegationJson: "{}",
      delegationSig: "",
      notBefore: 0,
      notAfter: 1,
    });
    expect(j.tip()).toEqual({ nextSeq: 0n, prevHash: ZERO_HASH, count: 0 });
    const h0 = append(j, 0n, ZERO_HASH, { n: 0 });
    const h1 = append(j, 1n, h0, { n: 1 });
    j.close();
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const j2 = open(path);
    expect(j2.tip()).toEqual({ nextSeq: 2n, prevHash: h1, count: 2 });
    expect([...j2.iterate()].map((r) => r.seq)).toEqual([0n, 1n]);
    expect(j2.readBody(1n).args).toEqual({ n: 1 });
    j2.close();
  });

  test("refuses another agent's journal", () => {
    const path = join(mkdtempSync(join(tmpdir(), "afr-j-")), "journal.sqlite");
    open(path).close();
    expect(() => open(path, { agentId: "local:9b2f4e0a-1c3d-4e5f-8a6b-7c8d9e0f1a2b" })).toThrow(
      expect.objectContaining({ code: "JOURNAL_AGENT_MISMATCH" }),
    );
    expect(() => open(path, { lane: 1 })).toThrow(
      expect.objectContaining({ code: "JOURNAL_AGENT_MISMATCH" }),
    );
  });

  test("bodies are sealed at rest (canary not in the db file) and bound to their seq", () => {
    const canary = createCanary();
    const path = join(mkdtempSync(join(tmpdir(), "afr-j-")), "journal.sqlite");
    const j = open(path);
    j.putSessionKey({
      address: signer.address,
      sessionId: SESSION,
      delegationJson: "{}",
      delegationSig: "",
      notBefore: 0,
      notAfter: 1,
    });
    append(j, 0n, ZERO_HASH, { secret: canary.value });
    expect(j.readBody(0n).args).toEqual({ secret: canary.value });
    j.close();
    const files = [path, `${path}-wal`].map((f) => {
      try {
        return readFileSync(f).toString("latin1");
      } catch {
        return "";
      }
    });
    canary.assertAbsent(...files);
    const wrongKey = Journal.open({
      path,
      agentId: AGENT,
      lane: 0,
      key: new Uint8Array(32),
      random,
    });
    expect(() => wrongKey.readBody(0n)).toThrow(
      expect.objectContaining({ code: "DECRYPT_FAILED" }),
    );
    wrongKey.close();
  });

  test("the background checkpointer keeps the WAL from growing (auto-checkpoint is off)", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "afr-j-")), "journal.sqlite");
    const j = open(path);
    j.putSessionKey({
      address: signer.address,
      sessionId: SESSION,
      delegationJson: "{}",
      delegationSig: "",
      notBefore: 0,
      notAfter: 1,
    });
    const wal = () => statSync(`${path}-wal`).size;
    let prev: `0x${string}` = ZERO_HASH;
    const batch = (from: number) => {
      for (let i = from; i < from + 300; i++)
        prev = append(j, BigInt(i), prev, { m: "x".repeat(2048) });
    };
    batch(0);
    const first = wal();
    await new Promise((r) => setTimeout(r, 2500)); // > CHECKPOINT_MS: the worker checkpoints
    batch(300); // a fully checkpointed WAL is rewritten from the start
    expect(wal()).toBeLessThan(first * 1.5);
    expect(j.readBody(599n).args).toEqual({ m: "x".repeat(2048) });
    j.close();
  }, 20_000);

  test("duplicate seq is rejected atomically", () => {
    const j = open(join(mkdtempSync(join(tmpdir(), "afr-j-")), "journal.sqlite"));
    j.putSessionKey({
      address: signer.address,
      sessionId: SESSION,
      delegationJson: "{}",
      delegationSig: "",
      notBefore: 0,
      notAfter: 1,
    });
    append(j, 0n, ZERO_HASH, { a: 1 });
    expect(() => append(j, 0n, ZERO_HASH, { a: 2 })).toThrow(
      expect.objectContaining({ code: expect.stringMatching(/^SQLITE_CONSTRAINT/) }),
    );
    expect(j.tip().count).toBe(1);
    j.close();
  });
});
