// P4-01/02 on anvil: W8 (restart mid-stream: no missed or repeated block), W3 (reorg: the watched tx above
// the common ancestor is orphaned), the EOA tx filter, and a reorg deeper than the ring stops the follower.
// Needs `anvil` (Foundry); skipped without it.
import { describe, expect, test } from "vitest";
import { HeadFollower, MemoryWatcherDb, type ObservedTx, WatchedSet } from "../src/index.js";
import { ANVIL, CHAIN, OTHER, useAnvil, WATCHED } from "./fixtures/anvil.js";

const anvil = useAnvil();
const { send, testClient: test_ } = anvil;

async function world(o: { ringSize?: number } = {}) {
  const db = new MemoryWatcherDb();
  db.watches.push({
    chainId: CHAIN,
    address: WATCHED.address,
    entry: { orgId: "org-1", agentId: "agent-1", kind: "eoa" },
  });
  const watched = new WatchedSet(db, CHAIN);
  await watched.reload();
  const observed: ObservedTx[] = [];
  const orphaned: ObservedTx[] = [];
  const follower = (startBlock?: bigint) =>
    new HeadFollower({
      chainId: CHAIN,
      client: anvil.pc,
      db,
      watched,
      ...(startBlock !== undefined ? { startBlock } : {}),
      ...(o.ringSize ? { ringSize: o.ringSize } : {}),
      onObserved: (t) => void observed.push(...t),
      onOrphaned: (t) => void orphaned.push(...t),
    });
  return { db, follower, observed, orphaned };
}

const drain = async (f: HeadFollower) => {
  for (let i = 0; i < 20; i++) if ((await f.tick()).processed === 0) return;
};

describe.skipIf(!ANVIL)("head follower (anvil)", () => {
  test("W8 + tx filter: a restart resumes from the cursor; only watched senders are observed", async () => {
    const w = await world();
    const start = (await anvil.pc.getBlockNumber()) + 1n;
    const a = await send();
    await send(OTHER); // not watched
    const f1 = w.follower(start);
    await drain(f1);
    expect(w.observed.map((t) => t.hash)).toEqual([a]);
    expect(w.observed[0]).toMatchObject({
      from: WATCHED.address.toLowerCase(),
      agentIds: ["agent-1"],
    });

    // the process "dies"; the chain keeps going
    const b = await send();
    await test_().mine({ blocks: 3 });
    const c = await send();
    const f2 = w.follower(start); // startBlock is ignored: the cursor wins
    await drain(f2);
    expect(w.observed.map((t) => t.hash)).toEqual([a, b, c]);
    const head = await anvil.pc.getBlockNumber();
    // every block from start to head committed exactly once, in order
    expect(w.db.commits).toEqual(
      Array.from({ length: Number(head - start + 1n) }, (_, i) => start + BigInt(i)),
    );
  });

  test("W3: a reorg orphans the watched tx above the common ancestor, then follows the new chain", async () => {
    const w = await world();
    const t = test_();
    const base = await anvil.pc.getBlockNumber();
    const f = w.follower(base + 1n);
    const snap = await t.snapshot();
    const tx = await send();
    await t.mine({ blocks: 2 });
    await drain(f);
    expect(w.observed.map((x) => x.hash)).toEqual([tx]);

    await t.revert({ id: snap }); // back to `base`; the tx is gone
    await t.mine({ blocks: 5 }); // a longer chain with different hashes
    const r = await f.tick();
    expect(r.reorgs).toEqual([base]);
    expect(w.orphaned.map((x) => x.hash)).toEqual([tx]);
    expect(w.db.observed.get(`${CHAIN}:${tx}`)?.status).toBe("orphaned");
    await drain(f);
    const head = await anvil.pc.getBlock({ blockTag: "latest" });
    const cur = await w.db.cursor(CHAIN);
    expect(cur).toMatchObject({ number: head.number, hash: head.hash });
  });

  test("a reorg deeper than the ring stops with REORG_TOO_DEEP instead of guessing", async () => {
    const w = await world({ ringSize: 2 });
    const t = test_();
    const base = await anvil.pc.getBlockNumber();
    const f = w.follower(base + 1n);
    const snap = await t.snapshot();
    await t.mine({ blocks: 5 });
    await drain(f);
    await t.revert({ id: snap });
    await send(OTHER); // empty blocks re-mined in the same second hash the same: make the new chain differ
    await t.mine({ blocks: 6 });
    await expect(f.tick()).rejects.toMatchObject({ code: "REORG_TOO_DEEP" });
  });
});
