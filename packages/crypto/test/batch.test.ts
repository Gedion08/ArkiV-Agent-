// L4 §3, §4, §10 + at-rest sealing. Layouts are cross-checked against independent implementations
// (ethers ABI coder, node:crypto AES-GCM and HMAC) so a self-consistent layout bug can't pass.
// shortcut: K1 fixed vectors (crypto.json) wait for HPKE, since that file also carries keygrant enc‖ct.
import { createDecipheriv, createHmac } from "node:crypto";
import { AbiCoder, concat as eConcat, keccak256 as eKeccak, toUtf8Bytes } from "ethers";
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";
import {
  type BatchCtx,
  batchAad,
  CryptoError,
  decryptBatch,
  encryptBatch,
  kekIdFor,
  newEpochKek,
  nonceCommit,
  openAtRest,
  sealAtRest,
  txCommit,
  userOpCommit,
} from "../src/index.js";

const AGENT_KEY = `0x${"a1".repeat(32)}` as Hex;
const ctx: BatchCtx = {
  agentKey: AGENT_KEY,
  lane: 3,
  seqFrom: 100n,
  seqTo: 199n,
  batchRoot: `0x${"b2".repeat(32)}`,
};
const plain = new TextEncoder().encode("padded batch plaintext: headers + bodies");
const kek = newEpochKek(AGENT_KEY, 27);
const declared = (s: ReturnType<typeof encryptBatch>, k = kek) => ({
  ...s,
  epochId: k.epochId,
  kekId: k.kekId,
});

function nodeGcmOpen(key: Uint8Array, iv: Uint8Array, ctTag: Uint8Array, aad: Uint8Array) {
  const d = createDecipheriv("aes-256-gcm", key, iv).setAAD(aad);
  d.setAuthTag(ctTag.subarray(ctTag.length - 16));
  return Buffer.concat([d.update(ctTag.subarray(0, ctTag.length - 16)), d.final()]);
}

const codeOf = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(CryptoError);
    return (e as CryptoError).code;
  }
  return "NO_ERROR";
};

describe("L4 §3–§4 batch encryption", () => {
  test("round-trips; layout matches independent ethers + node:crypto implementations", () => {
    const sealed = encryptBatch(plain, ctx, kek);
    expect(decryptBatch(declared(sealed), ctx, kek)).toEqual(plain);
    expect(sealed.wrappedDek.length).toBe(60);
    expect(sealed.payloadCtHash).toBe(eKeccak(sealed.ct));

    const aad = eKeccak(
      AbiCoder.defaultAbiCoder().encode(
        ["string", "bytes32", "uint32", "uint64", "uint64", "bytes32", "uint32", "bytes32"],
        [
          "AFR_BATCH_AAD_V1",
          ctx.agentKey,
          ctx.lane,
          ctx.seqFrom,
          ctx.seqTo,
          ctx.batchRoot,
          27,
          kek.kekId,
        ],
      ),
    );
    expect(batchAad(ctx, 27, kek.kekId)).toBe(aad);

    const tag = createHmac("sha256", kek.key).update("AFR_KEK_ID_V1").digest();
    expect(kek.kekId).toBe(
      eKeccak(eConcat([toUtf8Bytes("AFR_KEK_ID_V1"), AGENT_KEY, "0x0000001b", tag])),
    );

    const dekAad = Buffer.from(
      eConcat([toUtf8Bytes("AFR_DEK_V1"), AGENT_KEY, "0x0000001b", aad]).slice(2),
      "hex",
    );
    const dek = nodeGcmOpen(
      kek.key,
      sealed.wrappedDek.subarray(0, 12),
      sealed.wrappedDek.subarray(12),
      dekAad,
    );
    expect(dek.length).toBe(32);
    expect(nodeGcmOpen(dek, sealed.iv, sealed.ct, Buffer.from(aad.slice(2), "hex"))).toEqual(
      Buffer.from(plain),
    );
  });

  test("K2: changing any AAD component fails", () => {
    const sealed = declared(encryptBatch(plain, ctx, kek));
    for (const bad of [
      { ...ctx, lane: 4 },
      { ...ctx, seqFrom: 101n },
      { ...ctx, seqTo: 200n },
      { ...ctx, batchRoot: `0x${"b3".repeat(32)}` as Hex },
    ]) {
      expect(codeOf(() => decryptBatch(sealed, bad, kek))).toBe("AAD_MISMATCH");
    }
    // agent / epoch / kek_id changes are caught before decryption
    expect(
      codeOf(() => decryptBatch(sealed, { ...ctx, agentKey: `0x${"a2".repeat(32)}` }, kek)),
    ).toBe("KEK_ID_MISMATCH");
    expect(codeOf(() => decryptBatch({ ...sealed, epochId: 28 }, ctx, kek))).toBe(
      "KEK_ID_MISMATCH",
    );
    expect(codeOf(() => decryptBatch({ ...sealed, kekId: `0x${"00".repeat(32)}` }, ctx, kek))).toBe(
      "KEK_ID_MISMATCH",
    );
    // a forged epochId on the KEK object itself doesn't match its kek_id
    expect(
      codeOf(() => decryptBatch({ ...sealed, epochId: 28 }, ctx, { ...kek, epochId: 28 })),
    ).toBe("KEK_ID_MISMATCH");
  });

  test("K3: a wrapped DEK swapped in from another batch fails", () => {
    const a = declared(encryptBatch(plain, ctx, kek));
    const b = declared(encryptBatch(plain, { ...ctx, seqFrom: 200n, seqTo: 299n }, kek));
    expect(codeOf(() => decryptBatch({ ...a, wrappedDek: b.wrappedDek }, ctx, kek))).toBe(
      "AAD_MISMATCH",
    );
  });

  test("wrong KEK, tampered payload", () => {
    const sealed = declared(encryptBatch(plain, ctx, kek));
    const other = newEpochKek(AGENT_KEY, 27);
    expect(codeOf(() => decryptBatch(sealed, ctx, other))).toBe("KEK_ID_MISMATCH");
    const ct = sealed.ct.slice();
    ct[0] = (ct[0] ?? 0) ^ 1;
    expect(codeOf(() => decryptBatch({ ...sealed, ct }, ctx, kek))).toBe("DECRYPT_FAILED");
  });

  test("K9: truncated / oversized / random inputs only raise typed errors", () => {
    const sealed = declared(encryptBatch(plain, ctx, kek));
    const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
    const mutations = (b: Uint8Array) => [
      b.subarray(0, 0),
      b.subarray(0, b.length - 1),
      new Uint8Array([...b, 0]),
      rnd(b.length),
      rnd(b.length * 3),
    ];
    let n = 0;
    for (const field of ["ct", "iv", "wrappedDek"] as const) {
      for (const m of mutations(sealed[field])) {
        expect(codeOf(() => decryptBatch({ ...sealed, [field]: m }, ctx, kek))).not.toBe(
          "NO_ERROR",
        );
        n++;
      }
    }
    expect(n).toBe(15);
  });

  test("K10: errors carry no key material or plaintext", () => {
    const secret = "afr-canary-plaintext-7f3a";
    const sealed = declared(encryptBatch(new TextEncoder().encode(secret), ctx, kek));
    const keyHex = Buffer.from(kek.key).toString("hex");
    for (const f of [
      () => decryptBatch(sealed, { ...ctx, lane: 9 }, kek),
      () => decryptBatch({ ...sealed, ct: sealed.ct.subarray(1) }, ctx, kek),
      () => decryptBatch(sealed, ctx, newEpochKek(AGENT_KEY, 27)),
      () => kekIdFor(AGENT_KEY, 1, new Uint8Array(16)),
    ]) {
      try {
        f();
      } catch (e) {
        const text = `${(e as Error).message} ${(e as Error).stack}`;
        expect(text).not.toContain(secret);
        expect(text).not.toContain(keyHex);
      }
    }
  });
});

describe("L4 §10 watch-key commitments", () => {
  const wk = new Uint8Array(32).fill(5);
  const hmacHex = (...parts: Buffer[]) =>
    `0x${createHmac("sha256", wk).update(Buffer.concat(parts)).digest("hex")}`;
  const u64 = (n: bigint) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(n);
    return b;
  };
  const txHash = `0x${"c3".repeat(32)}` as Hex;
  const from = `0x${"d4".repeat(20)}` as Hex;

  test("match node:crypto HMAC over the exact layouts", () => {
    expect(txCommit(wk, 8453n, txHash)).toBe(
      hmacHex(Buffer.from("AFR_TX_V1"), u64(8453n), Buffer.from(txHash.slice(2), "hex")),
    );
    expect(userOpCommit(wk, 8453n, txHash)).toBe(txCommit(wk, 8453n, txHash));
    expect(nonceCommit(wk, 8453n, from, 7n)).toBe(
      hmacHex(Buffer.from("AFR_NONCE_V1"), u64(8453n), Buffer.from(from.slice(2), "hex"), u64(7n)),
    );
  });

  test("reject malformed inputs with typed errors", () => {
    expect(codeOf(() => txCommit(new Uint8Array(16), 1n, txHash))).toBe("INVALID_KEY");
    expect(codeOf(() => txCommit(wk, 1n, "0x1234"))).toBe("INVALID_KEY");
    expect(codeOf(() => nonceCommit(wk, 1n, txHash, 0n))).toBe("INVALID_KEY");
  });
});

describe("at-rest sealing", () => {
  const key = new Uint8Array(32).fill(8);
  test("round-trips, binds aad, rejects tampering and short input", () => {
    const aad = new TextEncoder().encode("epoch 27");
    const sealed = sealAtRest(key, plain, aad);
    expect(openAtRest(key, sealed, aad)).toEqual(plain);
    expect(codeOf(() => openAtRest(key, sealed))).toBe("DECRYPT_FAILED");
    expect(codeOf(() => openAtRest(key, sealed.subarray(0, 20), aad))).toBe("DECRYPT_FAILED");
  });
});
