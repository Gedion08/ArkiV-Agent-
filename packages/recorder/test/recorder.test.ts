import { readFileSync } from "node:fs";
import { hashTyped, verifyRecords, verifyTyped } from "@afr/core";
import { createCanary } from "@afr/log";
import { describe, expect, test } from "vitest";
import { identityChainId } from "../src/keys.js";
import { Recorder } from "../src/recorder.js";
import { AGENT, env, OPERATOR_ADDR, tmpConfig } from "./fixtures/setup.js";

async function allVerify(rec: Recorder) {
  const records = [...rec.journal.iterate()].map((r) => ({
    header: r.header,
    sig: r.sig,
    hash: r.hash,
  }));
  return { records, findings: await verifyRecords(records) };
}

const toolCall = (i: number) => ({
  type: "tool_call" as const,
  tool: { server: "everything", name: "echo" },
  body: { args: { message: `hi ${i}` } },
});

describe("P1-12/13 recorder", () => {
  test("start writes a signed session_start bound to an operator delegation", async () => {
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    await rec.delegationReady();
    const [first] = rec.journal.iterate();
    expect(first?.header).toMatchObject({
      seq: "0",
      type: "session_start",
      meta: { session_key: rec.status().sessionKey },
    });
    const sk = rec.journal.sessionKey(rec.status().sessionKey);
    expect(sk?.delegationSig).toMatch(/^0x[0-9a-f]{130}$/);
    const msg = JSON.parse(sk?.delegationJson ?? "{}");
    const typed = {
      ...msg,
      notBefore: BigInt(msg.notBefore),
      notAfter: BigInt(msg.notAfter),
      nonce: BigInt(msg.nonce),
    };
    expect(hashTyped(identityChainId(AGENT), "Delegation", typed)).toBe(
      first?.header.meta?.delegation_hash,
    );
    expect(
      await verifyTyped(
        identityChainId(AGENT),
        "Delegation",
        typed,
        sk?.delegationSig as `0x${string}`,
        OPERATOR_ADDR,
      ),
    ).toBe(true);
    expect(rec.status().delegation).toBe("signed");
    await rec.close();
  });

  test("R1: 10k concurrent async capture() calls give a contiguous, valid chain", async () => {
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    const results = await Promise.all(
      Array.from({ length: 10_000 }, (_, i) =>
        Promise.resolve().then(() => rec.capture(toolCall(i))),
      ),
    );
    const seqs = results.map((r) => r.seq).sort((a, b) => (a < b ? -1 : 1));
    expect(seqs[0]).toBe(1n);
    expect(seqs.every((s, i) => s === BigInt(i + 1))).toBe(true);
    expect((await allVerify(rec)).findings).toEqual([]);
    await rec.close();
  }, 120_000);

  test("restart continues the chain with recovered_from_seq", async () => {
    const config = tmpConfig();
    const a = await Recorder.start({ config, env, autoRotate: false });
    a.capture(toolCall(1));
    await a.close("test");
    const b = await Recorder.start({ config, env, autoRotate: false });
    b.capture(toolCall(2));
    const { records, findings } = await allVerify(b);
    expect(findings).toEqual([]);
    expect(records.map((r) => r.header.type)).toEqual([
      "session_start",
      "tool_call",
      "session_end",
      "session_start",
      "tool_call",
    ]);
    expect(records[3]?.header.meta?.recovered_from_seq).toBe("2");
    await b.close();
  });

  test("R11: rotation keeps chain continuity and switches the signing key", async () => {
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    const k1 = rec.status().sessionKey;
    rec.capture(toolCall(1));
    await rec.rotate();
    const k2 = rec.status().sessionKey;
    rec.capture(toolCall(2));
    expect(k2).not.toBe(k1);
    const { records, findings } = await allVerify(rec);
    expect(findings).toEqual([]);
    expect(records.map((r) => [r.header.type, r.header.meta?.reason])).toEqual([
      ["session_start", undefined],
      ["tool_call", undefined],
      ["session_end", "rotate"],
      ["session_start", undefined],
      ["tool_call", undefined],
    ]);
    expect([...rec.journal.iterate()].map((r) => r.sessionKey)).toEqual([k1, k1, k1, k2, k2]);
    await rec.close();
  });

  test("fail-open: journal failures reserve seqs, then a signed gap record covers them", async () => {
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    const j = rec.journal as unknown as { appendRecord: (...a: unknown[]) => void };
    const real = j.appendRecord.bind(j);
    let fail = true;
    j.appendRecord = (...a) => {
      if (fail) throw Object.assign(new Error("disk full"), { code: "SQLITE_FULL" });
      real(...a);
    };
    expect(rec.capture(toolCall(1))).toEqual({ seq: 1n });
    expect(rec.capture(toolCall(2))).toEqual({ seq: 2n });
    expect(rec.status().pendingGap).toEqual({ from: 1n, to: 2n });
    fail = false;
    const after = rec.capture(toolCall(3));
    expect(after.seq).toBe(4n);
    const { records, findings } = await allVerify(rec);
    expect(records.map((r) => [r.header.seq, r.header.type])).toEqual([
      ["0", "session_start"],
      ["3", "gap"],
      ["4", "tool_call"],
    ]);
    expect(findings).toEqual([expect.objectContaining({ code: "GAP", detail: "1..2" })]);
    await rec.close();
  });

  test("fail-closed: journal failures throw", async () => {
    const rec = await Recorder.start({
      config: tmpConfig({ fail_mode: "closed" }),
      env,
      autoRotate: false,
    });
    (rec.journal as unknown as { appendRecord: () => void }).appendRecord = () => {
      throw Object.assign(new Error("io"), { code: "SQLITE_IOERR" });
    };
    expect(() => rec.capture(toolCall(1))).toThrow("io");
  });

  test("tx records lowercase addresses, stringify numbers and commit calldata", async () => {
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    const r = rec.capture({
      type: "tx_sign",
      tx: {
        chain_id: 84532n,
        from: "0xABCDEF0000000000000000000000000000000001",
        nonce: 3,
        value: 10n ** 18n,
        tx_hash: `0x${"AB".repeat(32)}`,
      },
      body: { calldata: "0xa9059cbb" },
    });
    expect(r.record?.header.tx).toMatchObject({
      chain_id: "84532",
      from: "0xabcdef0000000000000000000000000000000001",
      nonce: "3",
      value: "1000000000000000000",
      tx_hash: `0x${"ab".repeat(32)}`,
      data_commit: r.record?.header.commit.calldata,
    });
    await rec.close();
  });

  test("binary MCP content is hashed and plaintext never lands in the journal file unencrypted", async () => {
    const canary = createCanary();
    const rec = await Recorder.start({ config: tmpConfig(), env, autoRotate: false });
    const r = rec.capture({
      type: "tool_result",
      refSeq: 0n,
      tool: { server: "s", name: "screenshot" },
      body: {
        result: {
          content: [
            {
              type: "image",
              data: Buffer.from("png-bytes").toString("base64"),
              mimeType: "image/png",
            },
            { type: "text", text: canary.value },
          ],
        },
      },
    });
    expect((r.record!.body.result as { content: unknown[] }).content[0]).toEqual({
      type: "image",
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      bytes: 9,
      mimeType: "image/png",
    });
    const path = rec.status().journalPath;
    await rec.close();
    canary.assertAbsent(readFileSync(path).toString("latin1"));
  });

  test("operator_env without a key fails with a clear error", async () => {
    await expect(
      Recorder.start({ config: tmpConfig(), env: {}, autoRotate: false }),
    ).rejects.toThrow(expect.objectContaining({ code: "OPERATOR_KEY_MISSING" }));
  });
});
