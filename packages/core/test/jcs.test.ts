import canonicalize from "canonicalize";
import { describe, expect, test } from "vitest";
import { jcs, jcsData } from "../src/index.js";

describe("T1 RFC 8785", () => {
  test("§3.2.2 sample (numbers, escapes, literals)", () => {
    const input = JSON.parse(
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
    );
    expect(jcsData(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  const sortInput = {
    "€": "Euro Sign",
    "\r": "Carriage Return",
    דּ: "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "😀": "Emoji: Grinning Face",
    "\u0080": "Control",
    ö: "Latin Small Letter O With Diaeresis",
  };

  const ordered = (keys: string[]) =>
    `{${keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(sortInput[k as keyof typeof sortInput] ?? "Hebrew Letter Dalet With Dagesh")}`).join(",")}}`;

  test("§3.2.3 key sorting (plain RFC 8785, no NFC)", () => {
    expect(canonicalize(sortInput)).toBe(
      ordered(["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"]),
    );
  });

  test("AFR adds NFC: U+FB33 normalises to U+05D3 U+05BC and sorts earlier", () => {
    expect(jcsData(sortInput)).toBe(
      ordered(["\r", "1", "\u0080", "\u00f6", "\u05d3\u05bc", "\u20ac", "\ud83d\ude00"]),
    );
  });
});

describe("T2 guards", () => {
  test.each([
    ["float", { a: 1.5 }],
    ["NaN", { a: Number.NaN }],
    ["Infinity", { a: Number.POSITIVE_INFINITY }],
    ["negative", { a: -1 }],
    ["≥ 2^31", { a: 2 ** 31 }],
    ["bigint", { a: 1n }],
    ["undefined", { a: undefined }],
    ["null", { a: null }],
    ["Date", { a: new Date(0) }],
    ["array hole", { a: [undefined] }],
  ])("strict jcs rejects %s", (_, v) => {
    expect(() => jcs(v)).toThrow(expect.objectContaining({ code: "JCS_INVALID" }));
  });

  test("data mode allows floats and null but not NaN/bigint/undefined", () => {
    expect(jcsData({ a: 1.5, b: null })).toBe('{"a":1.5,"b":null}');
    expect(() => jcsData({ a: Number.NaN })).toThrow();
    expect(() => jcsData({ a: 1n })).toThrow();
    expect(() => jcsData({ a: undefined })).toThrow();
  });

  test("normalises strings and keys to NFC", () => {
    expect(jcs({ é: "é" })).toBe(jcs({ é: "é" }));
  });

  test("rejects lone surrogates", () => {
    expect(() => jcsData({ a: "\ud800" })).toThrow(
      expect.objectContaining({ code: "JCS_INVALID" }),
    );
    expect(() => jcsData({ a: "x\udc00" })).toThrow(/lone surrogate/);
  });

  test("rejects keys that collide after NFC", () => {
    expect(() => jcs({ é: "1", é: "2" })).toThrow(/duplicate key/);
  });

  test("error messages never echo values", () => {
    try {
      jcs({ secret: 1.5 });
    } catch (e) {
      expect(String((e as Error).message)).not.toContain("1.5");
    }
  });
});
