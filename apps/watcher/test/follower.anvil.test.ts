// P4-01/02 on anvil: W8 (restart mid-stream: no missed or repeated block), W3 (reorg: the watched tx above
// the common ancestor is orphaned), the EOA tx filter, and a reorg deeper than the ring stops the follower.
// Needs `anvil` (Foundry); skipped without it.
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  type Hex,
  http,
  type PublicClient,
  parseEther,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { HeadFollower, MemoryWatcherDb, type ObservedTx, WatchedSet } from "../src/index.js";

const ANVIL = [process.env.ANVIL, join(homedir(), ".foundry/bin/anvil")].find(
  (p) => p && existsSync(p),
);
// anvil's well-known dev accounts 0 and 1
const WATCHED = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const OTHER = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const SINK = `0x${"ee".repeat(20)}` as Hex;
const CHAIN = BigInt(foundry.id);

let proc: ChildProcess;
let url: string;
let pc: PublicClient;
beforeAll(async () => {
  if (!ANVIL) return;
  const port = 20000 + Math.floor(Math.random() * 20000);
  url = `http://127.0.0.1:${port}`;
  proc = spawn(ANVIL, ["--port", String(port), "--silent"], { stdio: "ignore" });
  pc = createPublicClient({ chain: foundry, transport: http(url) }) as PublicClient;
  for (let i = 0; i < 100 && !(await pc.getChainId().catch(() => 0)); i++)
    await new Promise((r) => setTimeout(r, 100));
});
afterAll(() => proc?.kill());

const test_ = () => createTestClient({ chain: foundry, mode: "anvil", transport: http(url) });
const send = async (from = WATCHED) => {
  const w = createWalletClient({ account: from, chain: foundry, transport: http(url) });
  const hash = await w.sendTransaction({ to: SINK, value: parseEther("0.001") });
  await pc.waitForTransactionReceipt({ hash });
  return hash;
};

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
      client: pc,
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
    const start = (await pc.getBlockNumber()) + 1n;
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
    const head = await pc.getBlockNumber();
    // every block from start to head committed exactly once, in order
    expect(w.db.commits).toEqual(
      Array.from({ length: Number(head - start + 1n) }, (_, i) => start + BigInt(i)),
    );
  });

  test("W3: a reorg orphans the watched tx above the common ancestor, then follows the new chain", async () => {
    const w = await world();
    const t = test_();
    const base = await pc.getBlockNumber();
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
    const head = await pc.getBlock({ blockTag: "latest" });
    const cur = await w.db.cursor(CHAIN);
    expect(cur).toMatchObject({ number: head.number, hash: head.hash });
  });

  test("a reorg deeper than the ring stops with REORG_TOO_DEEP instead of guessing", async () => {
    const w = await world({ ringSize: 2 });
    const t = test_();
    const base = await pc.getBlockNumber();
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
