// P3-07..09 verifyAgent (L7 §3): V1 (negative vectors + batch-level tampering → exact codes), V4 (forged
// spam is ignored), V5 (equivocation fails), anchors (proof, mismatch, time-bounded delegations), full mode.
import { readFileSync } from "node:fs";
import { AfrError, hashHeader, type RecordHeaderV1 } from "@afr/core";
import { generateReaderKey } from "@afr/crypto";
import { encodeBody, encodeFrame, MemoryStore } from "@afr/store";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, test } from "vitest";
import { type VerifyOptions, verifyAgent } from "../src/index.js";
import { Agent, ANCHOR_CONTRACTS, frameRecord, T0, VECTOR_SK, WRITER } from "./fixtures/agent.js";

const SK2 = `0x${"00".repeat(31)}02` as Hex;
const SPAM = `0x${"00".repeat(31)}66` as Hex;
const NOW = new Date(Number(T0 + 3600n) * 1000);
const OTHER_KEY = privateKeyToAccount(`0x${"0d".repeat(32)}`);

const opts = (a: Agent, o: Partial<VerifyOptions> = {}): VerifyOptions => ({
  store: a.store,
  identity: a.identity,
  anchors: a.anchors,
  anchorContracts: ANCHOR_CONTRACTS,
  now: () => NOW,
  ...o,
});
const codes = (r: { findings: { code: string; severity: string }[] }, sev = "fail") =>
  [...new Set(r.findings.filter((f) => f.severity === sev).map((f) => f.code))].sort();

/** A delegated, profiled agent with `n` batches of 3 records on lane 0. */
async function agent(n = 3) {
  const a = new Agent();
  await a.delegate(VECTOR_SK);
  await a.profile();
  for (let i = 0; i < n; i++) await a.batch(0, 3, VECTOR_SK);
  return a;
}

/** A batch entity with explicit attrs (to disagree with its frame). */
const rawBatch = (
  a: Agent,
  attrs: { seqFrom: bigint; seqTo: bigint; root: Hex },
  payload: Uint8Array,
) =>
  a.put({
    schema: "afr.batch.v1",
    attrs: {
      agent_key: a.ak,
      lane: 0n,
      seq_from: attrs.seqFrom,
      seq_to: attrs.seqTo,
      chain_root: attrs.root,
      prev_chain_root: attrs.root,
      batch_root: attrs.root,
      session_key: `0x${"11".repeat(20)}`,
      epoch_id: 1n,
      record_count: 3n,
      privacy: 0n,
    },
    payload,
    readonly: true,
    lock: true,
    permissionlessExtension: true,
  });

describe("verifyAgent structural", () => {
  test("PASS: delegations, contiguous signed batches, anchored head; the tail is info", async () => {
    const a = await agent(2);
    const { epoch, tx } = await a.anchor([0]);
    await a.batch(0, 3, VECTOR_SK);
    const r = await verifyAgent(a.agentId, opts(a));
    expect(r.result).toBe("PASS");
    expect(r.level).toBe("structural");
    expect(r.lanes).toEqual([
      {
        lane: 0,
        records: "9",
        batches: 3,
        seq_range: ["0", "8"],
        last_anchor: {
          epoch: epoch.toString(),
          tx,
          block_time: new Date(Number(T0 + 600n) * 1000).toISOString(),
          seq_to: "5",
        },
        unanchored_tail: { count: "3" },
      },
    ]);
    expect(codes(r, "info")).toEqual(["UNANCHORED_TAIL"]);
  });

  test("V1: batch-level tampering → exact codes", async () => {
    const cases: [string, (a: Agent) => Promise<unknown>, string[]][] = [
      // CT_HASH: unreachable through the store, encodeFrame/decodeFrame already reject ct ≠ payload_ct_hash
      [
        "record hash swapped in the public section",
        async (a) => {
          const f = a.seal(0, a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK);
          (f.pub.records[1] as { hash: Hex }).hash = `0x${"ee".repeat(32)}`;
          await a.putFrame(f);
        },
        ["MERKLE_MISMATCH", "RECORD_SIG"],
      ],
      [
        "a batch missing",
        async (a) => {
          a.records(0, 3, VECTOR_SK); // made, never uploaded
          await a.batch(0, 3, VECTOR_SK);
        },
        ["SEQ_GAP"],
      ],
      [
        "prev_chain_root doesn't link",
        (a) =>
          a.putFrame(
            a.seal(0, a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK, {
              prevChainRoot: `0x${"77".repeat(32)}`,
            }),
          ),
        ["CHAIN_BREAK"],
      ],
      [
        "attrs disagree with the frame (allowlisted writer)",
        async (a) => {
          const f = a.seal(0, a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK);
          const p = f.pub;
          await rawBatch(
            a,
            {
              seqFrom: BigInt(p.seq_from),
              seqTo: BigInt(p.seq_to) + 1n,
              root: p.chain_root as Hex,
            },
            encodeFrame(f),
          );
        },
        ["ATTR_MISMATCH"],
      ],
      [
        "garbage payload (allowlisted writer)",
        (a) =>
          rawBatch(
            a,
            { seqFrom: 3n, seqTo: 5n, root: `0x${"33".repeat(32)}` },
            new Uint8Array([1, 2, 3]),
          ),
        ["FRAME_DECODE"],
      ],
    ];
    for (const [name, tamper, want] of cases) {
      const a = await agent(1);
      await tamper(a);
      const r = await verifyAgent(a.agentId, opts(a));
      expect([name, codes(r)]).toEqual([name, want]);
      expect(r.result).toBe("FAIL");
    }
  });

  test("V4: 100 forged batches (valid format, undelegated signer) are ignored", async () => {
    const a = await agent(2);
    const real = new Map(a.tip);
    const spammer = new MemoryStore(a.chain, `0x${"5a".repeat(20)}`);
    for (let i = 0; i < 100; i++) {
      a.tip.set(0, {
        seq: 0n,
        prevHash: `0x${"00".repeat(32)}`,
        chainRoot: `0x${"00".repeat(32)}`,
      });
      // forged over the real seq range: a counted forgery would be an equivocation
      await a.putFrame(a.seal(0, a.records(0, 3, SPAM).map(frameRecord), SPAM), spammer);
    }
    for (const [k, v] of real) a.tip.set(k, v);
    const filtered = await verifyAgent(a.agentId, opts(a));
    expect(filtered.result).toBe("PASS"); // not even listed: not an allowlisted writer
    expect(codes(filtered, "info")).toEqual(["UNANCHORED_TAIL"]);
    const all = await verifyAgent(a.agentId, opts(a, { noWriterFilter: true }));
    expect(all.result).toBe("PASS");
    expect(all.findings).toContainEqual({
      code: "IGNORED_UNSIGNED",
      severity: "info",
      lane: 0,
      detail: "100 batches",
    });
    expect(all.lanes[0]?.batches).toBe(2);
  }, 30_000); // signs 300 records

  test("V5: a second validly signed batch for the same seq_from → EQUIVOCATION; an identical copy is fine", async () => {
    const a = await agent(1);
    const before = { ...(a.tip.get(0) as { seq: bigint; prevHash: Hex; chainRoot: Hex }) };
    const f = await a.batch(0, 3, VECTOR_SK);
    await a.putFrame(f); // byte-identical re-create (rollback): tolerated
    expect((await verifyAgent(a.agentId, opts(a))).result).toBe("PASS");

    await a.delegate(SK2);
    a.tip.set(0, before);
    await a.batch(0, 3, SK2); // a fork of [3, 5] under another delegated key
    const r = await verifyAgent(a.agentId, opts(a));
    expect(codes(r)).toEqual(["EQUIVOCATION"]);
    expect(r.findings.find((x) => x.code === "EQUIVOCATION")?.seq).toBe("3");
  });

  test("delegations not signed by the operator are ignored, and so are their batches", async () => {
    const a = new Agent();
    await a.profile();
    await a.delegate(VECTOR_SK, { by: OTHER_KEY });
    await a.batch(0, 3, VECTOR_SK);
    const lane0 = await verifyAgent(a.agentId, opts(a, { lane: 0 }));
    expect(codes(lane0, "warn")).toEqual(["DELEGATION_BAD_SIG", "NO_VALID_BATCHES"]);
    expect(lane0.result).toBe("PASS_WITH_WARNINGS");
    const any = await verifyAgent(a.agentId, opts(a));
    expect(codes(any, "warn")).toEqual(["DELEGATION_BAD_SIG", "NO_VALID_DELEGATION"]);
  });

  test("identity: unknown agent → FAIL ID_UNRESOLVED; an RPC error is thrown, never FAIL", async () => {
    const a = await agent(1);
    const failing = (e: Error) =>
      opts(a, {
        identity: {
          ...a.identity,
          resolve: async () => {
            throw e;
          },
        },
      });
    const unknown = await verifyAgent(
      a.agentId,
      failing(new AfrError("AGENT_NOT_REGISTERED", "no owner")),
    );
    expect(codes(unknown)).toEqual(["ID_UNRESOLVED"]);
    await expect(verifyAgent(a.agentId, failing(new TypeError("fetch failed")))).rejects.toThrow(
      "fetch failed",
    );
  });

  test("writers: the profile allowlist hides other writers' entities", async () => {
    const a = await agent(1);
    const otherWriter = `0x${"b2".repeat(20)}` as Hex;
    const f = a.seal(0, a.records(0, 3, VECTOR_SK).map(frameRecord), VECTOR_SK);
    await a.putFrame(f, new MemoryStore(a.chain, otherWriter));
    expect((await verifyAgent(a.agentId, opts(a))).lanes[0]?.batches).toBe(1);
    const both = await verifyAgent(a.agentId, opts(a, { writers: [WRITER, otherWriter] }));
    expect(both.lanes[0]?.batches).toBe(2);
  });
});

describe("verifyAgent anchors (P3-09)", () => {
  test("ANCHOR_MISMATCH: an anchored chain root that isn't ours", async () => {
    const a = await agent(2);
    await a.anchor([0], { chainRoot: `0x${"99".repeat(32)}` });
    expect(codes(await verifyAgent(a.agentId, opts(a)))).toEqual(["ANCHOR_MISMATCH"]);
  });

  test("bad proof: from an allowlisted anchor key → ANCHOR_PROOF; from anyone else → ignored", async () => {
    const a = await agent(2);
    await a.anchor([0], { badProof: true });
    expect(codes(await verifyAgent(a.agentId, opts(a)))).toEqual(["ANCHOR_PROOF"]);

    const b = await agent(2);
    await b.anchor([0], { badProof: true, by: OTHER_KEY });
    const r = await verifyAgent(b.agentId, opts(b));
    expect(r.result).toBe("PASS");
    expect(codes(r, "info")).toEqual(["IGNORED_CHECKPOINT", "UNANCHORED_TAIL"]);
  });

  test("a valid proof under an unknown signing key still counts, with CHECKPOINT_SIG (warn)", async () => {
    const a = await agent(2);
    await a.anchor([0], { by: OTHER_KEY });
    const r = await verifyAgent(a.agentId, opts(a));
    expect(codes(r, "warn")).toEqual(["CHECKPOINT_SIG"]);
    expect(r.lanes[0]?.last_anchor?.seq_to).toBe("5");
  });

  test("delegation time bound: anchored after notAfter + 1 h → DELEGATION_INVALID", async () => {
    const a = new Agent();
    await a.delegate(VECTOR_SK, { notAfter: T0 + 600n });
    await a.profile();
    await a.batch(0, 3, VECTOR_SK);
    await a.anchor([0], { blockTime: T0 + 600n + 3601n });
    expect(codes(await verifyAgent(a.agentId, opts(a)))).toEqual(["DELEGATION_INVALID"]);
  });

  test("no anchor reader → ANCHOR_NOT_CHECKED (warn)", async () => {
    const a = await agent(1);
    await a.anchor([0]);
    const { anchors: _, ...noAnchors } = opts(a);
    const r = await verifyAgent(a.agentId, noAnchors);
    expect(r.result).toBe("PASS_WITH_WARNINGS");
    expect(codes(r, "warn")).toEqual(["ANCHOR_NOT_CHECKED"]);
  });
});

describe("verifyAgent full (P3-08)", () => {
  test("PASS with a reader key; no keygrant → warn, structural still holds", async () => {
    const a = await agent(2);
    await a.anchor([0]);
    const reader = await generateReaderKey();
    const noGrant = await verifyAgent(a.agentId, opts(a, { reader }));
    expect(codes(noGrant, "warn")).toEqual(["NO_KEYGRANT"]);
    await a.grant(reader.pub, VECTOR_SK);
    const r = await verifyAgent(a.agentId, opts(a, { reader }));
    expect(r.level).toBe("full");
    expect(r.findings).toEqual([]);
    expect(r.result).toBe("PASS");
  });

  test("record ts outside the delegation window → DELEGATION_INVALID (full mode sees ts)", async () => {
    const a = new Agent();
    await a.delegate(VECTOR_SK, { notBefore: T0 + 3600n }); // records are stamped at T0
    await a.profile();
    await a.batch(0, 3, VECTOR_SK);
    const reader = await generateReaderKey();
    await a.grant(reader.pub, VECTOR_SK);
    expect(codes(await verifyAgent(a.agentId, opts(a)))).toEqual([]); // structural can't see ts
    expect(codes(await verifyAgent(a.agentId, opts(a, { reader })))).toEqual([
      "DELEGATION_INVALID",
    ]);
  });

  test("V1: every negative record vector, sealed in a signed batch → its exact codes", async () => {
    const { cases } = JSON.parse(
      readFileSync(
        new URL("../../test-vectors/vectors/negative/records.json", import.meta.url),
        "utf8",
      ),
    ) as {
      cases: {
        name: string;
        input: { records?: { header: Record<string, unknown>; sig: Hex; hash?: Hex }[] };
        expected: { codes: string[] };
      }[];
    };
    const reader = await generateReaderKey();
    for (const c of cases) {
      if (!c.input.records) continue; // body-only vectors: commitments, covered in core
      const a = new Agent();
      await a.delegate(VECTOR_SK);
      await a.profile();
      await a.grant(reader.pub, VECTOR_SK);
      const recs = c.input.records.map((r, i) => ({
        seq: BigInt(i), // public positions stay contiguous: the vectors break the headers
        // no claimed hash: the batch carries the tampered header's own
        hash: r.hash ?? hashHeader(r.header as RecordHeaderV1),
        sig: r.sig,
        headerJcs: JSON.stringify(r.header), // as given: some are deliberately invalid
        body: encodeBody({ salt: `0x${"00".repeat(32)}` }),
      }));
      await a.putFrame(a.seal(0, recs, VECTOR_SK));
      const r = await verifyAgent(a.agentId, opts(a, { reader }));
      // the record vectors carry no bodies: commitment checks are out of their scope
      const got = codes(r).filter((x) => x !== "COMMIT_MISMATCH");
      expect([c.name, got]).toEqual([c.name, [...c.expected.codes].sort()]);
    }
  });
});
