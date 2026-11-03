// L1 §3.5: RFC 8785 JCS with AFR guards [NORMATIVE].
import canonicalize from "canonicalize";
import { AfrError } from "./errors.js";

const SMALL_INT_LIMIT = 2 ** 31;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

type Mode = "strict" | "data";

function fail(path: string, why: string): never {
  throw new AfrError("JCS_INVALID", `jcs: ${why} at ${path || "<root>"}`);
}

function prepare(value: unknown, mode: Mode, path: string): unknown {
  switch (typeof value) {
    case "string":
      if (LONE_SURROGATE.test(value)) fail(path, "lone surrogate (not valid UTF-8)");
      return value.normalize("NFC");
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) fail(path, "non-finite number");
      if (
        mode === "strict" &&
        !(Number.isInteger(value) && value >= 0 && value < SMALL_INT_LIMIT)
      ) {
        fail(path, "only integers in [0, 2^31) are allowed; use a decimal string");
      }
      return value;
    case "object": {
      if (value === null) {
        if (mode === "strict") fail(path, "null (omit optional fields instead)");
        return null;
      }
      if (Array.isArray(value)) return value.map((v, i) => prepare(v, mode, `${path}[${i}]`));
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) fail(path, "non-plain object");
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        const nk = k.normalize("NFC");
        if (Object.hasOwn(out, nk)) fail(path, "duplicate key after NFC normalisation");
        out[nk] = prepare(v, mode, `${path}.${nk}`);
      }
      return out;
    }
    default:
      // undefined, bigint, function, symbol
      return fail(path, `unsupported ${typeof value}`);
  }
}

/**
 * Canonical JSON for hashed AFR structures (headers, statements, policy docs).
 * Throws on floats, ints ≥ 2^31, negatives, null, undefined, bigint. Normalises strings to NFC.
 */
export function jcs(value: unknown): string {
  return canonicalize(prepare(value, "strict", "")) as string;
}

/**
 * Canonical JSON for arbitrary captured data (tool args/results, model I/O) inside commitments.
 * Plain RFC 8785 number handling (finite numbers, null allowed) plus NFC strings.
 * Throws on NaN/Infinity, undefined, bigint and non-plain objects.
 */
export function jcsData(value: unknown): string {
  return canonicalize(prepare(value, "data", "")) as string;
}
