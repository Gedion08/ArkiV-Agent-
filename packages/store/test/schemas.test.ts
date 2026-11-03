// P2-03: schema spec ⇔ L3 §5 [NORMATIVE] parity, Arkiv limits, privacy allowlists (C9 unit part).
import { readFileSync } from "node:fs";
import { MAX_ATTRIBUTES, validateAttributeName } from "@arkiv-network/sdk/schema";
import { describe, expect, test } from "vitest";
import {
  ARKIV_SCHEMAS,
  type AttrsOf,
  assertAttrs,
  assertPrivacy,
  SCHEMA_NAMES,
  SCHEMA_SPEC,
  validatePut,
} from "../src/index.js";

const doc = readFileSync(
  new URL("../../../docs/02-layers/L3-evidence-store-arkiv.md", import.meta.url),
  "utf8",
);

/** Parse every `defineSchema("name", { attr: type().indexed().optional(), ... })` in L3 §5. */
function docSchemas() {
  const out: Record<string, Record<string, string>> = {};
  for (const m of doc.matchAll(/defineSchema\("([^"]+)",\s*\{([\s\S]*?)\n\}\);/g)) {
    const cols: Record<string, string> = {};
    for (const c of (m[2] as string).matchAll(
      /^\s*([a-z_0-9]+):\s*([a-z0-9]+)\(\)((?:\.\w+\(\))*)/gm,
    ))
      cols[c[1] as string] = `${c[2]}${c[3]}`;
    out[m[1] as string] = cols;
  }
  return out;
}

const VALID: AttrsOf<"afr.batch.v1"> = {
  agent_key: `0x${"a1".repeat(32)}`,
  lane: 0n,
  seq_from: 0n,
  seq_to: 9n,
  chain_root: `0x${"b2".repeat(32)}`,
  prev_chain_root: `0x${"00".repeat(32)}`,
  batch_root: `0x${"c3".repeat(32)}`,
  session_key: `0x${"d4".repeat(20)}`,
  epoch_id: 352n,
  record_count: 10n,
  privacy: 0n,
};
const code = (f: () => unknown) => {
  try {
    f();
    return "NO_ERROR";
  } catch (e) {
    return (e as { code?: string }).code;
  }
};

describe("L3 §5 schemas", () => {
  test("spec matches the normative doc exactly (names, types, indexed, optional, payload)", () => {
    const fromDoc = docSchemas();
    expect(Object.keys(fromDoc).sort()).toEqual([...SCHEMA_NAMES].sort());
    for (const name of SCHEMA_NAMES) {
      const { attrs, payload } = SCHEMA_SPEC[name];
      const ours: Record<string, string> = { [payload]: "bytes" };
      for (const [k, v] of Object.entries(attrs) as [
        string,
        { type: string; indexed?: true; optional?: true },
      ][])
        ours[k] = `${v.type}${v.indexed ? ".indexed()" : ""}${v.optional ? ".optional()" : ""}`;
      expect(ours, name).toEqual(fromDoc[name]);
    }
  });

  test("Arkiv limits: ≤ 31 attrs with the schema tag, valid names, one bytes column", () => {
    expect(MAX_ATTRIBUTES).toBe(32);
    for (const name of SCHEMA_NAMES) {
      const cols = Object.keys((ARKIV_SCHEMAS[name] as unknown as { columns: object }).columns);
      expect(cols.length, name).toBeLessThanOrEqual(MAX_ATTRIBUTES - 1);
      for (const c of cols) expect(() => validateAttributeName(c)).not.toThrow();
      expect(cols).toContain(SCHEMA_SPEC[name].payload);
    }
  });
});

describe("attribute validation and privacy allowlists", () => {
  test("level 0 rejects the level-1 flags; level 1 accepts them; privacy attr must match level", () => {
    const req = { schema: "afr.batch.v1" as const, attrs: { ...VALID, has_tx: true } };
    expect(code(() => assertPrivacy(req, 0))).toBe("PRIVACY_ATTR");
    expect(code(() => assertPrivacy({ ...req, attrs: { ...req.attrs, privacy: 1n } }, 1))).toBe(
      "NO_ERROR",
    );
    expect(code(() => assertPrivacy({ schema: "afr.batch.v1", attrs: VALID }, 1))).toBe(
      "PRIVACY_ATTR",
    );
    expect(code(() => assertPrivacy({ schema: "afr.batch.v1", attrs: VALID }, 0))).toBe("NO_ERROR");
  });

  test("action entities only at level 2", () => {
    const req = { schema: "afr.action.v1" as const, attrs: {} as never };
    expect(code(() => assertPrivacy(req, 1))).toBe("SCHEMA_NOT_ALLOWED");
    expect(code(() => assertPrivacy(req, 2))).toBe("NO_ERROR");
  });

  test("types, presence, unknown attrs, str length, u64 range, lowercase hex", () => {
    expect(code(() => assertAttrs("afr.batch.v1", VALID))).toBe("NO_ERROR");
    const bad: Record<string, unknown>[] = [
      { ...VALID, lane: -1n },
      { ...VALID, lane: 2n ** 64n },
      { ...VALID, lane: 1 },
      { ...VALID, session_key: "0x12" },
      { ...VALID, batch_root: "x".repeat(129) },
      { ...VALID, agent_key: `0x${"A1".repeat(32)}` },
      { ...VALID, extra: "no" },
      { ...VALID, seq_to: undefined },
    ];
    for (const b of bad)
      expect(
        code(() => assertAttrs("afr.batch.v1", b)),
        JSON.stringify(Object.keys(b)),
      ).toBe("ATTR_INVALID");
  });

  test("validatePut: payload size cap and expiry", () => {
    const base = {
      schema: "afr.batch.v1" as const,
      attrs: VALID,
      expiresAt: { days: 30 },
      readonly: true,
      permissionlessExtension: true,
      lock: true,
      idempotencyKey: `0x${"ee".repeat(32)}` as const,
    };
    expect(code(() => validatePut({ ...base, payload: new Uint8Array(120 * 1024) }, 0))).toBe(
      "NO_ERROR",
    );
    expect(code(() => validatePut({ ...base, payload: new Uint8Array(120 * 1024 + 1) }, 0))).toBe(
      "PAYLOAD_TOO_LARGE",
    );
    expect(
      code(() => validatePut({ ...base, payload: new Uint8Array(1), expiresAt: { days: 0 } }, 0)),
    ).toBe("EXPIRY_INVALID");
  });
});
