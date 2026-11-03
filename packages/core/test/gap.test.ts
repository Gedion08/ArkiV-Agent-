import { expect, test } from "vitest";
import {
  buildHeader,
  hashHeader,
  type RecordHeaderV1,
  verifyLinks,
  ZERO_HASH,
} from "../src/index.js";
import { base, toolCall } from "./fixtures/headers.js";

function chainWithGap(from: string, to: string, gapSeq: bigint): RecordHeaderV1[] {
  const a = buildHeader(toolCall(), { seq: 0n, prevHash: ZERO_HASH });
  const gap = buildHeader(
    {
      ...base,
      type: "gap",
      commit: {},
      meta: { from_seq: from, to_seq: to, reason: "journal_write_failed" },
    },
    { seq: gapSeq, prevHash: hashHeader(a) },
  );
  const b = buildHeader(toolCall(), { seq: gapSeq + 1n, prevHash: hashHeader(gap) });
  return [a, gap, b];
}

test("a gap record at to_seq + 1 covering the reserved seqs is accepted as info", () => {
  expect(verifyLinks(chainWithGap("1", "3", 4n)).findings).toEqual([
    expect.objectContaining({ code: "GAP", severity: "info", seq: "4", detail: "1..3" }),
  ]);
});

test.each([
  ["from_seq skips ahead", "2", "3", 4n],
  ["seq not to_seq + 1", "1", "3", 5n],
  ["to_seq < from_seq", "3", "1", 2n],
])("a gap record that lies about its range is a SEQ_GAP (%s)", (_, from, to, seq) => {
  expect(verifyLinks(chainWithGap(from, to, seq)).findings.map((f) => f.code)).toContain("SEQ_GAP");
});
