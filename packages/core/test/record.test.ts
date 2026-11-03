import { describe, expect, test } from "vitest";
import {
  type BuildInput,
  buildBody,
  buildHeader,
  COMMIT_DOMAIN,
  commit,
  commitmentsFor,
  hashHeader,
  keccakJcsData,
  REQUIRED_FIELDS,
  U64Schema,
  verifyBody,
  ZERO_HASH,
} from "../src/index.js";
import { base, H32, SALT, sessionStart, toolCall } from "./fixtures/headers.js";

const chain0 = { seq: 0n, prevHash: ZERO_HASH };

describe("T8 buildHeader", () => {
  test("builds a valid tool_call and hashes deterministically", () => {
    const h = buildHeader(toolCall(), chain0);
    expect(h).toMatchObject({ v: 1, seq: "0", prev_hash: ZERO_HASH, type: "tool_call" });
    expect(hashHeader(h)).toBe(hashHeader(buildHeader(toolCall(), chain0)));
  });

  test("omits undefined optional fields", () => {
    const h = buildHeader({ ...toolCall(), ref_seq: undefined } as never, chain0);
    expect("ref_seq" in h).toBe(false);
  });

  test.each(Object.entries(REQUIRED_FIELDS).filter(([, f]) => f.length > 0))(
    "%s rejects a header missing %s",
    (type, fields) => {
      const input = { ...base, type, commit: {} } as unknown as BuildInput;
      expect(() => buildHeader(input, chain0)).toThrow(
        expect.objectContaining({
          code: "HEADER_INVALID",
          message: expect.stringContaining(fields[0]!),
        }),
      );
    },
  );

  test.each([
    ["uppercase hex", { session_id: `0x${"AB".repeat(16)}` }],
    ["numeric seq-like field", { ts: 1793577600000 }],
    ["leading-zero u64", { ts: "01" }],
    ["unknown field", { extra: "x" }],
    [
      "checksummed agent registry",
      { agent_id: "eip155:8453:0x8004A169FB4A3325136EB29FA0CEB6D2E539A432:42" },
    ],
    ["lane ≥ 2^31", { lane: 2 ** 31 }],
  ])("rejects %s", (_, patch) => {
    expect(() => buildHeader({ ...toolCall(), ...patch } as never, chain0)).toThrow(
      expect.objectContaining({ code: "HEADER_INVALID" }),
    );
  });

  test("rejects too many / too long meta entries", () => {
    const meta = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, "v"]));
    expect(() => buildHeader({ ...toolCall(), meta }, chain0)).toThrow();
    expect(() => buildHeader({ ...toolCall(), meta: { k: "x".repeat(129) } }, chain0)).toThrow();
  });

  test("session_start requires meta fields", () => {
    expect(() => buildHeader(sessionStart(), chain0)).not.toThrow();
    const { meta, ...rest } = sessionStart();
    expect(() => buildHeader({ ...rest, meta: { recorder_version: "x" } }, chain0)).toThrow(
      /config_hash/,
    );
    expect(meta).toBeDefined();
  });

  test("NFC: composed and decomposed inputs hash the same", () => {
    const a = buildHeader({ ...toolCall(), tool: { server: "s", name: "café" } }, chain0);
    const b = buildHeader({ ...toolCall(), tool: { server: "s", name: "café" } }, chain0);
    expect(hashHeader(a)).toBe(hashHeader(b));
  });
});

describe("commitments and bodies", () => {
  test("commit format: keccak(0x01‖salt‖domain‖0x00‖JCS)", () => {
    const c = commit(COMMIT_DOMAIN.ARGS, { b: 1, a: "x" }, SALT);
    expect(c).toBe(commit(COMMIT_DOMAIN.ARGS, { a: "x", b: 1 }, SALT));
    expect(c).not.toBe(commit(COMMIT_DOMAIN.RESULT, { a: "x", b: 1 }, SALT));
    expect(c).not.toBe(commit(COMMIT_DOMAIN.ARGS, { a: "x", b: 1 }, H32("22")));
    expect(() => commit(COMMIT_DOMAIN.ARGS, 1, "0x01")).toThrow(
      expect.objectContaining({ code: "SALT_INVALID" }),
    );
  });

  test("buildBody commitments round-trip through verifyBody", () => {
    const { body, commit: c } = buildBody({ args: { q: 1.5 }, calldata: "0xdeadbeef" }, SALT);
    expect(commitmentsFor(body)).toEqual(c);
    const h = buildHeader({ ...toolCall(), commit: c }, chain0);
    expect(verifyBody(h, body)).toEqual([]);
    expect(verifyBody(h, { ...body, args: { q: 2 } })).toMatchObject([
      { code: "COMMIT_MISMATCH", detail: "args" },
    ]);
  });

  test("truncation: commitment covers the full value, body keeps a prefix", () => {
    const big = { text: "é".repeat(100) };
    const full = buildBody({ result: big }, SALT, { maxBytes: 1 << 20 });
    const t = buildBody({ result: big, calldata: `0x${"ab".repeat(100)}` }, SALT, { maxBytes: 51 });
    expect(t.commit.result).toBe(full.commit.result);
    expect(typeof t.body.result).toBe("string");
    expect(new TextEncoder().encode(t.body.result as string).length).toBeLessThanOrEqual(51);
    expect((t.body.result as string).endsWith("�")).toBe(false);
    expect(t.body.calldata).toMatch(/^0x([0-9a-f]{2}){24}$/);
    expect(t.body.truncated).toEqual([
      { field: "result", original_hash: keccakJcsData(big), original_bytes: expect.any(Number) },
      { field: "calldata", original_hash: expect.any(String), original_bytes: 204 },
    ]);
    expect(commitmentsFor(t.body)).toEqual({});
    const h = buildHeader({ ...toolCall(), commit: { args: H32("aa"), ...t.commit } }, chain0);
    expect(verifyBody(h, t.body).map((f) => f.code)).toEqual([
      "COMMIT_MISMATCH",
      "TRUNCATED",
      "TRUNCATED",
    ]);
  });

  test("redaction entries are passed through and reported", () => {
    const { body } = buildBody(
      {
        args: { key: "[REDACTED:openai-key]" },
        redacted: [{ field: "args", path: "/key", reason: "openai-key" }],
      },
      SALT,
    );
    const h = buildHeader({ ...toolCall(), commit: commitmentsFor(body) }, chain0);
    expect(verifyBody(h, body)).toMatchObject([{ code: "REDACTED", severity: "info" }]);
  });
});

describe("U64Schema", () => {
  test("malformed strings fail safeParse instead of throwing", () => {
    for (const s of [";0", "0x1", "1e3", " 1", "01", "-1", "18446744073709551616"])
      expect(U64Schema.safeParse(s).success).toBe(false);
    expect(U64Schema.safeParse("18446744073709551615").success).toBe(true);
  });
});
