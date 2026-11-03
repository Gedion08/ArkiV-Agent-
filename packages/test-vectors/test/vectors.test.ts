// Recomputes every committed vector with @afr/core (L1 §11). A failure means the implementation drifted.
import { readFileSync } from "node:fs";
import {
  agentKey,
  batchDigest,
  batchProof,
  batchRoot,
  chainRoot,
  commit,
  EIP712_TYPES,
  EVIDENCE_LOCK_ADDRESS,
  hashHeader,
  hashTyped,
  jcs,
  jcsData,
  localSigner,
  parseAgentId,
  type RecordHeaderV1,
  recoverRecordSigner,
  type StatementType,
  validateHeader,
  verifyBatchProof,
  verifyBody,
  verifyRecords,
  verifyTyped,
} from "@afr/core";
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";

// biome-ignore lint/suspicious/noExplicitAny: vector JSON is untyped by design
type Case = { name: string; input: any; expected: any };
const load = (f: string): Case[] =>
  JSON.parse(readFileSync(new URL(`../vectors/${f}`, import.meta.url), "utf8")).cases;
const session = localSigner(`0x${"00".repeat(31)}01`);
const entries = (xs: { seq: string; hash: Hex }[]) =>
  xs.map((e) => ({ seq: BigInt(e.seq), hash: e.hash }));

describe("vectors", () => {
  test.each(load("jcs.json"))("jcs $name", ({ input, expected }) => {
    expect((input.mode === "strict" ? jcs : jcsData)(JSON.parse(input.json))).toBe(expected);
  });

  test.each(load("agent_id.json"))("agent_id $name", ({ input, expected }) => {
    expect(agentKey(input)).toBe(expected.agent_key);
    if (input.startsWith("eip155")) {
      const p = parseAgentId(input);
      expect({
        chainId: String(p.chainId),
        registry: p.registry,
        tokenId: String(p.tokenId),
      }).toEqual({
        chainId: expected.chainId,
        registry: expected.registry,
        tokenId: expected.tokenId,
      });
    }
  });

  test.each(load("commit.json"))("commit $name", ({ input, expected }) => {
    expect(commit(input.domain, JSON.parse(input.value_json), input.salt)).toBe(expected);
  });

  test.each(load("records.json"))("record $name", async ({ input, expected }) => {
    const header = validateHeader(input.header);
    expect(header).toEqual(input.header);
    expect(hashHeader(header)).toBe(expected.record_hash);
    expect(session.signDigest(expected.record_hash)).toBe(expected.sig);
    expect(await recoverRecordSigner(expected.record_hash, expected.sig)).toBe(expected.signer);
    if (input.body) expect(verifyBody(header, input.body)).toEqual([]);
  });

  test("records form a valid chain", async () => {
    const recs = load("records.json").map((c) => ({
      header: c.input.header,
      sig: c.expected.sig,
      hash: c.expected.record_hash,
    }));
    // the gap record (seq 7, covering reserved seq 6) is the only finding, and it is informational
    expect(await verifyRecords(recs)).toEqual([
      expect.objectContaining({ code: "GAP", severity: "info", seq: "7" }),
    ]);
  });

  test("chain batches", () => {
    let prev: Hex | undefined;
    for (const { input, expected } of load("chain.json")) {
      if (prev) expect(input.prev_chain_root).toBe(prev);
      const e = entries(input.entries);
      const root = batchRoot(e);
      const cr = chainRoot(input.prev_chain_root, root, e.at(-1)?.seq ?? 0n);
      const digest = batchDigest({
        agentKey: input.agent_key,
        lane: input.lane,
        seqFrom: e[0]?.seq ?? 0n,
        seqTo: e.at(-1)?.seq ?? 0n,
        batchRoot: root,
        prevChainRoot: input.prev_chain_root,
        chainRoot: cr,
        payloadCtHash: input.payload_ct_hash,
      });
      expect({ root, cr, digest, sig: session.signDigest(digest) }).toEqual({
        root: expected.batch_root,
        cr: expected.chain_root,
        digest: expected.batch_digest,
        sig: expected.batch_sig,
      });
      prev = cr;
    }
  });

  test.each(load("merkle.json"))("merkle $name", ({ input, expected }) => {
    const e = entries(input.entries);
    expect(batchRoot(e)).toBe(expected.root);
    e.forEach((x, i) => {
      expect(batchProof(e, x.seq)).toEqual(expected.proofs[i]);
      expect(verifyBatchProof(expected.root, x, expected.proofs[i])).toBe(true);
    });
  });

  test.each(load("eip712.json"))("eip712 $name", async ({ input, expected }) => {
    const type = input.primary_type as StatementType;
    // uint64+ fields are decimal strings in JSON
    const message = Object.fromEntries(
      EIP712_TYPES[type].map(({ name, type: t }) => {
        const v = input.message[name];
        return [name, /^uint(64|128|256)$/.test(t) ? BigInt(v) : v];
      }),
    );
    expect(hashTyped(input.chain_id, type, message)).toBe(expected.digest);
    expect(await verifyTyped(input.chain_id, type, message, expected.sig, expected.signer)).toBe(
      true,
    );
  });

  test("lock address", () => {
    expect(load("lock_address.json")[0]?.expected).toBe(EVIDENCE_LOCK_ADDRESS);
  });

  test.each(load("negative/records.json"))("negative $name", async ({ input, expected }) => {
    const codes = input.records
      ? (await verifyRecords(input.records)).map((f) => f.code)
      : verifyBody(input.header as RecordHeaderV1, input.body).map((f) => f.code);
    expect([...new Set(codes)].sort()).toEqual(expected.codes);
  });
});
