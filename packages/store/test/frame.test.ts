// P2-04: L3 §4 frame round-trip, determinism, padding buckets, size cap, typed errors on garbage.
import { type BatchPublicV1, LIMITS, PADDING_BUCKETS } from "@afr/core";
import { Encoder } from "cbor-x";
import fc from "fast-check";
import { type Hex, keccak256 } from "viem";
import { describe, expect, test } from "vitest";
import {
  decodeFrame,
  encodeCanonical,
  encodeFrame,
  packPlaintext,
  pad,
  unpackPlaintext,
  unpad,
} from "../src/index.js";

const h32 = (b: string) => `0x${b.repeat(32)}` as Hex;
const sig = `0x${"ab".repeat(64)}1b` as Hex;

function pubFor(ct: Uint8Array): BatchPublicV1 {
  return {
    v: 1,
    agent_id: `eip155:8453:0x${"11".repeat(20)}:42`,
    lane: 0,
    seq_from: "10",
    seq_to: "11",
    prev_chain_root: h32("01"),
    chain_root: h32("02"),
    batch_root: h32("03"),
    session_keys: [`0x${"d4".repeat(20)}`],
    records: [
      { seq: "10", hash: h32("04"), sig, sk: 0 },
      { seq: "11", hash: h32("05"), sig, sk: 0 },
    ],
    tx_commitments: [],
    nonce_commitments: [h32("06")],
    flags: { has_tx: false, has_block: false, has_unapproved_tx: false, has_violation: false },
    epoch_id: 352,
    kek_id: h32("07"),
    wrapped_dek: `0x${"0f".repeat(40)}`,
    iv: `0x${"0a".repeat(12)}`,
    payload_ct_hash: keccak256(ct),
    batch_sig: sig,
  };
}
const codeOf = (f: () => unknown) => {
  try {
    f();
    return "NO_ERROR";
  } catch (e) {
    return (e as { code?: string }).code ?? "UNTYPED";
  }
};
const reversed = <T extends object>(o: T): T =>
  Object.fromEntries(Object.entries(o).reverse()) as T;

describe("frame (L3 §4)", () => {
  test("round-trip: decode(encode(f)) = f, for arbitrary ct", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (ct) => {
        const f = { pub: pubFor(ct), ct };
        const back = decodeFrame(encodeFrame(f));
        expect(back.pub).toEqual(f.pub);
        expect(back.ct).toEqual(ct);
        expect(back.ct.constructor).toBe(Uint8Array);
      }),
      { numRuns: 100 },
    );
  });

  test("deterministic: input key order doesn't change the bytes; keys canonically sorted", () => {
    const ct = new Uint8Array([1, 2, 3]);
    const pub = pubFor(ct);
    const a = encodeFrame({ pub, ct });
    const shuffled = reversed({ ...pub, flags: reversed(pub.flags as object) }) as BatchPublicV1;
    expect(encodeFrame({ pub: shuffled, ct })).toEqual(a);
    // RFC 8949 §4.2.1: shorter keys first, then bytewise
    expect(encodeCanonical({ bb: 1, a: 2, c: 3 })).toEqual(encodeCanonical({ a: 2, c: 3, bb: 1 }));
    expect([...encodeCanonical({ bb: 1, a: 2 })].slice(0, 3)).toEqual([0xa2, 0x61, 0x61]);
  });

  test("rejects values without one deterministic encoding", () => {
    for (const x of [1.5, 2 ** 32, -1, 1n, null])
      expect(codeOf(() => encodeCanonical({ x }))).toBe("FRAME_INVALID");
  });

  test("pub is validated and payload_ct_hash must match ct", () => {
    const ct = new Uint8Array([9]);
    expect(codeOf(() => encodeFrame({ pub: pubFor(new Uint8Array([8])), ct }))).toBe(
      "FRAME_INVALID",
    );
    expect(codeOf(() => encodeFrame({ pub: { ...pubFor(ct), seq_from: 10 } as never, ct }))).toBe(
      "FRAME_INVALID",
    );
  });

  test("max size: frames ≤ BATCH_MAX_FRAME_BYTES encode; larger throw FRAME_TOO_LARGE", () => {
    const overhead = encodeFrame({ pub: pubFor(new Uint8Array(0)), ct: new Uint8Array(0) }).length;
    fc.assert(
      fc.property(fc.integer({ min: 0, max: LIMITS.BATCH_MAX_FRAME_BYTES + 512 }), (n) => {
        const ct = new Uint8Array(n);
        const code = codeOf(() => encodeFrame({ pub: pubFor(ct), ct }));
        // the byte-string head grows by up to 4 bytes as n crosses 24 / 256 / 65536
        if (n + overhead + 4 <= LIMITS.BATCH_MAX_FRAME_BYTES) expect(code).toBe("NO_ERROR");
        if (n + overhead > LIMITS.BATCH_MAX_FRAME_BYTES) expect(code).toBe("FRAME_TOO_LARGE");
      }),
      { numRuns: 60 },
    );
    expect(codeOf(() => decodeFrame(new Uint8Array(LIMITS.BATCH_MAX_FRAME_BYTES + 1)))).toBe(
      "FRAME_TOO_LARGE",
    );
  });

  test("decode: arbitrary bytes and mutated frames fail only with typed errors", () => {
    const ct = new Uint8Array([1, 2, 3, 4]);
    const good = encodeFrame({ pub: pubFor(ct), ct });
    fc.assert(
      fc.property(
        fc.oneof(
          fc.uint8Array({ maxLength: 512 }),
          fc.tuple(fc.nat(good.length - 1), fc.integer({ min: 1, max: 255 })).map(([i, x]) => {
            const m = good.slice();
            m[i] = (m[i] as number) ^ x;
            return m;
          }),
        ),
        (bytes) => {
          expect(["NO_ERROR", "FRAME_INVALID"]).toContain(codeOf(() => decodeFrame(bytes)));
        },
      ),
      { numRuns: 300 },
    );
  });

  test("decode rejects a non-canonical encoding of a valid frame", () => {
    const ct = new Uint8Array([1]);
    const good = encodeFrame({ pub: pubFor(ct), ct });
    const loose = new Encoder({
      useRecords: false,
      mapsAsObjects: true,
      variableMapSize: true,
      tagUint8Array: false,
    });
    // same content, top-level keys out of canonical order
    const bad = new Uint8Array(loose.encode({ pub: pubFor(ct), f: "afr.frame.v1", ct }));
    expect(bad.length).toBe(good.length);
    expect(codeOf(() => decodeFrame(bad))).toBe("FRAME_INVALID");
  });
});

describe("plaintext + padding (L3 §4)", () => {
  const arbPlain = fc
    .array(fc.tuple(fc.string({ maxLength: 200 }), fc.uint8Array({ maxLength: 300 })), {
      maxLength: 20,
    })
    .map((xs) => ({ headers: xs.map((x) => x[0]), bodies: xs.map((x) => x[1]) }));

  test("round-trip with and without padding", () => {
    fc.assert(
      fc.property(arbPlain, fc.boolean(), (p, padding) => {
        const back = unpackPlaintext(packPlaintext(p, { padding }));
        expect(back).toEqual(p);
        for (const b of back.bodies) expect(b.constructor).toBe(Uint8Array);
      }),
      { numRuns: 100 },
    );
  });

  test("padding: smallest bucket ≥ len+4 (else len+4), u32be prefix, zero fill", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 130 * 1024 }), fc.boolean(), (n, padding) => {
        const x = new Uint8Array(n).fill(0xee);
        const p = pad(x, padding);
        const bucket = PADDING_BUCKETS.find((b) => b >= n + 4);
        expect(p.length).toBe(padding && bucket ? bucket : n + 4);
        expect(new DataView(p.buffer).getUint32(0)).toBe(n);
        expect(p.subarray(4 + n).some((b) => b !== 0)).toBe(false);
        expect(Buffer.compare(unpad(p), x)).toBe(0);
      }),
      { numRuns: 40 },
    );
  });

  test("unpad / unpack reject malformed input with typed errors", () => {
    expect(codeOf(() => unpad(new Uint8Array(3)))).toBe("FRAME_INVALID");
    expect(codeOf(() => unpad(new Uint8Array([0, 0, 0, 9, 1])))).toBe("FRAME_INVALID");
    expect(codeOf(() => unpad(new Uint8Array([0, 0, 0, 1, 1, 7])))).toBe("FRAME_INVALID");
    expect(codeOf(() => packPlaintext({ headers: ["a"], bodies: [] }, { padding: false }))).toBe(
      "FRAME_INVALID",
    );
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 256 }), (z) => {
        expect(["NO_ERROR", "FRAME_INVALID"]).toContain(
          codeOf(() => unpackPlaintext(pad(z, false))),
        );
      }),
      { numRuns: 300 },
    );
  });
});
