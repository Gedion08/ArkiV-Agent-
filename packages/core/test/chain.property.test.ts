import fc from "fast-check";
import { describe, expect, test } from "vitest";
import {
  buildHeader,
  hashHeader,
  type RecordHeaderV1,
  verifyLinks,
  ZERO_HASH,
} from "../src/index.js";
import { toolCall } from "./fixtures/headers.js";

const RUNS = 10_000;

function makeChain(n: number, names: string[]): RecordHeaderV1[] {
  const out: RecordHeaderV1[] = [];
  let prev = ZERO_HASH;
  for (let i = 0; i < n; i++) {
    const h = buildHeader(
      { ...toolCall(), tool: { server: "s", name: names[i % names.length] ?? "t" } },
      { seq: BigInt(i), prevHash: prev },
    );
    out.push(h);
    prev = hashHeader(h);
  }
  return out;
}

describe("T3 header mutation changes record_hash", () => {
  test("mutating one character of any string field changes the hash", () => {
    const h = makeChain(1, ["echo"])[0] as RecordHeaderV1;
    const paths: [string, string?][] = [
      ["agent_id"],
      ["seq"],
      ["session_id"],
      ["ts"],
      ["prev_hash"],
      ["tool", "name"],
      ["tool", "server"],
      ["commit", "args"],
    ];
    const original = hashHeader(h);
    fc.assert(
      fc.property(
        fc.constantFrom(...paths),
        fc.nat(),
        fc.integer({ min: 1, max: 0xffff }),
        ([a, b], pos, delta) => {
          const copy = structuredClone(h) as unknown as Record<
            string,
            Record<string, string> | string
          >;
          const holder = (b ? copy[a] : copy) as Record<string, string>;
          const key = b ?? a;
          const s = holder[key] as string;
          const i = pos % s.length;
          const ch = String.fromCharCode((s.charCodeAt(i) + delta) % 0x10000);
          if (ch.normalize("NFC") === s[i]) return;
          holder[key] = s.slice(0, i) + ch + s.slice(i + 1);
          if (/[\uD800-\uDFFF]/.test(ch)) {
            // lone surrogates are not valid UTF-8: hashing must refuse, not silently collide
            expect(() => hashHeader(copy as unknown as RecordHeaderV1)).toThrow(/lone surrogate/);
            return;
          }
          expect(hashHeader(copy as unknown as RecordHeaderV1)).not.toBe(original);
        },
      ),
      { numRuns: RUNS },
    );
  }, 300_000);
});

describe("T4 reorder/remove/insert breaks the chain", () => {
  const arb = fc.record({
    n: fc.integer({ min: 2, max: 12 }),
    names: fc.array(fc.string({ minLength: 1, maxLength: 8 }), { minLength: 1, maxLength: 4 }),
    op: fc.constantFrom("swap", "remove", "insert", "duplicate"),
    i: fc.nat(),
    j: fc.nat(),
  });

  test("valid chains pass, mutated chains fail", () => {
    fc.assert(
      fc.property(arb, ({ n, names, op, i, j }) => {
        const chain = makeChain(n, names);
        expect(verifyLinks(chain).findings).toEqual([]);
        const a = i % n;
        const b = j % n;
        const m = [...chain];
        if (op === "swap") {
          if (a === b) return;
          [m[a], m[b]] = [m[b] as RecordHeaderV1, m[a] as RecordHeaderV1];
        } else if (op === "remove") {
          if (a === n - 1) return; // dropping the tail is undetectable without an anchor; anchors cover it
          m.splice(a, 1);
        } else if (op === "insert") {
          const forged = buildHeader(
            { ...toolCall(), tool: { server: "x", name: "forged" } },
            {
              seq: BigInt(a),
              prevHash: a === 0 ? ZERO_HASH : hashHeader(chain[a - 1] as RecordHeaderV1),
            },
          );
          m.splice(a, 0, forged);
        } else {
          m.splice(a, 0, chain[a] as RecordHeaderV1);
        }
        expect(verifyLinks(m).findings.length).toBeGreaterThan(0);
      }),
      { numRuns: RUNS },
    );
  }, 300_000);
});
