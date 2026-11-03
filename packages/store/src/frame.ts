// L3 §4 [NORMATIVE] batch frame: deterministic CBOR {f, pub, ct} + padded, deflated plaintext.
// cbor-x has no canonical mode, so maps are key-sorted here (RFC 8949 §4.2.1: shorter key first,
// then bytewise) and cbor-x emits shortest-form heads; floats and ints > 2³²−1 are refused, since
// cbor-x would encode them as float64 (u64 values travel as decimal strings, L1).
import {
  AfrError,
  type BatchPublicV1,
  BatchPublicV1Schema,
  LIMITS,
  PADDING_BUCKETS,
} from "@afr/core";
import { Encoder } from "cbor-x";
import { deflateSync, inflateSync } from "fflate";
import { keccak256 } from "viem";

export const FRAME_TAG = "afr.frame.v1";

const cbor = new Encoder({
  useRecords: false,
  mapsAsObjects: true,
  variableMapSize: true,
  tagUint8Array: false,
});
const utf8 = new TextEncoder();

const fail = (code: "FRAME_INVALID" | "FRAME_TOO_LARGE", msg: string): never => {
  throw new AfrError(code, msg);
};

function keyOrder(a: string, b: string) {
  const x = utf8.encode(a);
  const y = utf8.encode(b);
  if (x.length !== y.length) return x.length - y.length;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return (x[i] as number) - (y[i] as number);
  return 0;
}

/** Deep copy with sorted map keys; rejects values without a single deterministic encoding. */
function canonical(v: unknown, path: string): unknown {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map((x, i) => canonical(x, `${path}[${i}]`));
  if (typeof v === "string" || typeof v === "boolean") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0 || v > 0xffff_ffff)
      fail("FRAME_INVALID", `${path}: only uint32 numbers are allowed`);
    return v;
  }
  if (v !== null && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort(keyOrder)) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) out[k] = canonical(x, `${path}.${k}`);
    }
    return out;
  }
  return fail("FRAME_INVALID", `${path}: unsupported value type`);
}

export const encodeCanonical = (v: unknown): Uint8Array =>
  new Uint8Array(cbor.encode(canonical(v, "$")));

function decode(bytes: Uint8Array, what: string): unknown {
  try {
    return cbor.decode(bytes);
  } catch {
    return fail("FRAME_INVALID", `${what}: not CBOR`);
  }
}
/** cbor-x returns Node Buffers for byte strings; normalise to plain Uint8Array. */
const u8 = (x: unknown) => (x instanceof Uint8Array ? new Uint8Array(x) : undefined);
const isMap = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === "object" && !Array.isArray(x) && !(x instanceof Uint8Array);
const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

// ---------- padding ----------

/** pad(x) = u32be(len(x)) ‖ x ‖ zeros(bucket − 4 − len(x)); bucket = smallest PADDING_BUCKETS ≥ len+4, else len+4. */
export function pad(x: Uint8Array, padding: boolean): Uint8Array {
  const need = x.length + 4;
  const bucket = padding ? (PADDING_BUCKETS.find((b) => b >= need) ?? need) : need;
  const out = new Uint8Array(bucket);
  new DataView(out.buffer).setUint32(0, x.length);
  out.set(x, 4);
  return out;
}

export function unpad(p: Uint8Array): Uint8Array {
  if (p.length < 4) fail("FRAME_INVALID", "padded plaintext shorter than its length prefix");
  const len = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint32(0);
  if (len > p.length - 4) fail("FRAME_INVALID", "length prefix exceeds plaintext");
  for (let i = 4 + len; i < p.length; i++)
    if (p[i] !== 0) fail("FRAME_INVALID", "non-zero padding");
  return p.slice(4, 4 + len);
}

// ---------- plaintext ----------

export interface BatchPlaintext {
  /** The exact JCS strings that were hashed. */
  headers: string[];
  /** CBOR(RecordBodyV1) bytes, index-aligned with headers. */
  bodies: Uint8Array[];
}

/** Cap on inflated plaintext (a 120 KiB frame of real records inflates far less than 64×). */
const MAX_INFLATED = LIMITS.BATCH_MAX_FRAME_BYTES * 64;

/** plaintext_of_ct = pad(deflateRaw(CBOR({headers, bodies})), bucket). Encrypt the result (L4). */
export function packPlaintext(p: BatchPlaintext, opts: { padding: boolean }): Uint8Array {
  if (p.headers.length !== p.bodies.length)
    fail("FRAME_INVALID", "headers and bodies differ in length");
  const raw = encodeCanonical({ headers: p.headers, bodies: p.bodies });
  return pad(deflateSync(raw, { level: 9 }), opts.padding);
}

export function unpackPlaintext(padded: Uint8Array): BatchPlaintext {
  const z = unpad(padded);
  let raw: Uint8Array;
  try {
    // shortcut: fflate's sync inflate has no output cap; the size check runs after inflating. Use a
    // streaming Inflate with a cap if untrusted frames are ever inflated outside the verifier.
    raw = inflateSync(z);
  } catch {
    return fail("FRAME_INVALID", "plaintext does not inflate");
  }
  if (raw.length > MAX_INFLATED) fail("FRAME_INVALID", "inflated plaintext too large");
  const d = decode(raw, "plaintext");
  const headers = isMap(d) ? d.headers : undefined;
  const bodies = isMap(d) && Array.isArray(d.bodies) ? d.bodies.map(u8) : undefined;
  if (
    !isMap(d) ||
    Object.keys(d).length !== 2 ||
    !Array.isArray(headers) ||
    !headers.every((h) => typeof h === "string") ||
    !bodies?.every((b) => b !== undefined) ||
    bodies.length !== headers.length
  )
    fail("FRAME_INVALID", "plaintext is not {headers: string[], bodies: bytes[]}");
  return { headers: headers as string[], bodies: bodies as Uint8Array[] };
}

// ---------- frame ----------

export interface Frame {
  pub: BatchPublicV1;
  /** AES-256-GCM ciphertext ‖ tag; the IV is pub.iv. */
  ct: Uint8Array;
}

function checkPub(pub: unknown, ct: Uint8Array): BatchPublicV1 {
  const r = BatchPublicV1Schema.safeParse(pub);
  if (!r.success) return fail("FRAME_INVALID", "pub is not a valid BatchPublicV1");
  if (r.data.payload_ct_hash !== keccak256(ct))
    fail("FRAME_INVALID", "payload_ct_hash ≠ keccak256(ct)");
  return r.data;
}

/** frame = CBOR({f, pub, ct}), byte-identical for equal inputs. FRAME_TOO_LARGE above the cap. */
export function encodeFrame(f: Frame): Uint8Array {
  checkPub(f.pub, f.ct);
  const bytes = encodeCanonical({ f: FRAME_TAG, pub: f.pub, ct: f.ct });
  if (bytes.length > LIMITS.BATCH_MAX_FRAME_BYTES)
    fail(
      "FRAME_TOO_LARGE",
      `frame ${bytes.length} B > ${LIMITS.BATCH_MAX_FRAME_BYTES} B; split the batch`,
    );
  return bytes;
}

/** Strict inverse of encodeFrame; also rejects non-canonical encodings (re-encoding must match). */
export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.length > LIMITS.BATCH_MAX_FRAME_BYTES) fail("FRAME_TOO_LARGE", "frame over the cap");
  const d = decode(bytes, "frame");
  const ct = isMap(d) ? u8(d.ct) : undefined;
  if (!isMap(d) || d.f !== FRAME_TAG || !ct || Object.keys(d).length !== 3)
    fail("FRAME_INVALID", "not an afr.frame.v1");
  const frame = {
    pub: checkPub((d as Record<string, unknown>).pub, ct as Uint8Array),
    ct: ct as Uint8Array,
  };
  if (!same(encodeCanonical({ f: FRAME_TAG, pub: frame.pub, ct: frame.ct }), bytes))
    fail("FRAME_INVALID", "non-canonical frame encoding");
  return frame;
}
