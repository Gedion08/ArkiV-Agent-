// P2-09: L3 §8 listBatches keyset pagination + equivocation grouping (on MemoryStore).
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";
import {
  type BatchEntity,
  groupDuplicates,
  listBatches,
  MemoryChain,
  MemoryStore,
} from "../src/index.js";
import { batchReq } from "./conformance.js";

const W1 = `0x${"a1".repeat(20)}` as Hex;
const W2 = `0x${"b2".repeat(20)}` as Hex;
let agents = 0;

function setup() {
  const chain = new MemoryChain();
  const agentKey = `0x${(++agents).toString(16).padStart(64, "e")}` as Hex;
  const s1 = new MemoryStore(chain, W1);
  const s2 = new MemoryStore(chain, W2);
  const put = async (s: MemoryStore, seqFrom: number, len = 1, payload?: string) => {
    const req = batchReq({
      attrs: { agent_key: agentKey, seq_from: BigInt(seqFrom), seq_to: BigInt(seqFrom + len - 1) },
      ...(payload ? { payload: new TextEncoder().encode(payload) } : {}),
    });
    const ref = await s.await(await s.put(req));
    chain.advance(1);
    return ref.key;
  };
  return { s1, s2, agentKey, put };
}
async function collect<T>(it: AsyncIterable<T>) {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
}
const seqs = (bs: BatchEntity[]) => bs.map((b) => Number(b.attrs.seq_from));

describe("listBatches (L3 §8)", () => {
  test("250 batches over full pages: all, ascending, no duplicates; fromSeq respected", async () => {
    const { s1, agentKey, put } = setup();
    for (let i = 0; i < 250; i++) await put(s1, i * 2, 2);
    const all = await collect(listBatches(s1, { agentKey, lane: 0n }));
    expect(seqs(all)).toEqual(Array.from({ length: 250 }, (_, i) => i * 2));
    expect(new Set(all.map((b) => b.ref.key)).size).toBe(250);
    const tail = await collect(listBatches(s1, { agentKey, lane: 0n, fromSeq: 400n }));
    expect(seqs(tail)[0]).toBe(400);
    expect(tail).toHaveLength(50);
  });

  test("duplicates straddling a page boundary are all returned", async () => {
    const { s1, agentKey, put } = setup();
    for (let i = 0; i < 9; i++) await put(s1, i * 10, 10);
    const dups = [
      await put(s1, 90, 10, "a"),
      await put(s1, 90, 10, "b"),
      await put(s1, 90, 5, "c"),
    ];
    await put(s1, 100, 10);
    const got = await collect(listBatches(s1, { agentKey, lane: 0n, pageSize: 10 }));
    expect(got).toHaveLength(13);
    expect(
      got
        .filter((b) => b.attrs.seq_from === 90n)
        .map((b) => b.ref.key)
        .sort(),
    ).toEqual(dups.sort());
    expect(seqs(got).at(-1)).toBe(100);
  });

  test("more than a page of spam at one seq_from neither stalls nor hides later batches", async () => {
    const { s1, s2, agentKey, put } = setup();
    await put(s1, 0, 5);
    for (let i = 0; i < 25; i++) await put(s2, 5, 1, `spam-${i}`);
    await put(s1, 5, 5);
    await put(s1, 10, 5);
    const got = await collect(listBatches(s1, { agentKey, lane: 0n, pageSize: 10 }));
    expect(got).toHaveLength(28);
    expect(seqs(got).at(-1)).toBe(10);
    // the writer filter is a discovery optimisation that drops the spammer entirely
    const filtered = await collect(
      listBatches(s1, { agentKey, lane: 0n, writers: [W1], pageSize: 10 }),
    );
    expect(seqs(filtered)).toEqual([0, 5, 10]);
  });

  test("other lanes and agents are excluded", async () => {
    const a = setup();
    const b = setup();
    await a.put(a.s1, 0);
    await b.put(b.s1, 0);
    const lane1 = batchReq({
      attrs: { agent_key: a.agentKey, lane: 1n, seq_from: 0n, seq_to: 0n },
    });
    await a.s1.await(await a.s1.put(lane1));
    expect(await collect(listBatches(a.s1, { agentKey: a.agentKey, lane: 0n }))).toHaveLength(1);
  });
});

describe("groupDuplicates (L3 §8, L7 step 3)", () => {
  test("identical duplicates collapse; differing valid ones are EQUIVOCATION; invalid ignored", async () => {
    const { s1, s2, agentKey, put } = setup();
    await put(s1, 0, 5, "genesis");
    const k1 = await put(s1, 5, 5, "same");
    const k1b = await put(s1, 5, 5, "same"); // rollback re-create: byte-identical
    const forged = await put(s2, 10, 5, "forged");
    const ka = await put(s1, 10, 5, "fork-a");
    const kb = await put(s1, 10, 5, "fork-b");
    const all = await collect(listBatches(s1, { agentKey, lane: 0n }));
    // stand-in for the L7 batch_sig + delegation checks
    const { batches, equivocations } = await groupDuplicates(all, (b) => b.meta.creator === W1);
    expect(seqs(batches)).toEqual([0, 5, 10]);
    expect([k1, k1b]).toContain(batches[1]?.ref.key); // either copy; ties order by entity key
    expect(equivocations).toHaveLength(1);
    expect(equivocations[0]).toMatchObject({ code: "EQUIVOCATION", lane: 0n, seqFrom: 10n });
    expect([...(equivocations[0]?.keys ?? [])].sort()).toEqual([ka, kb].sort());
    expect(equivocations[0]?.keys).not.toContain(forged);
  });
});
