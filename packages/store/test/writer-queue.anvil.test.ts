// P2-08 WriterQueue on anvil: a STOP stub at the registry address stands in for Arkiv, so the real
// sign → journal → broadcast → receipt path runs. Checks the write-safety rules (L3 §7, SPIKES S4).
// Needs `anvil` (Foundry); CI installs it.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { createPublicClient, type Hex, http, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { MemoryWriteJournal, REGISTRY, type WriteEntry, WriterQueue } from "../src/index.js";

const ANVIL = [process.env.ANVIL, "anvil", join(homedir(), ".foundry/bin/anvil")].find(
  (b) => b && spawnSync(b, ["--version"]).status === 0,
);
const PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // anvil #1
const account = privateKeyToAccount(PK);
let anvil: ChildProcess;
let pc: ReturnType<typeof createPublicClient>;
const rpc = (method: string, params: unknown[]) => pc.request({ method, params } as never);
const id = (s: string) => keccak256(toHex(s));
const KEY = `0x${"ab".repeat(32)}` as Hex;

beforeAll(async () => {
  if (!ANVIL) return;
  const port = 20000 + Math.floor(Math.random() * 20000);
  anvil = spawn(ANVIL, ["--port", String(port), "--silent"], { stdio: "ignore" });
  pc = createPublicClient({ chain: foundry, transport: http(`http://127.0.0.1:${port}`) });
  for (let i = 0; i < 100 && !(await pc.getChainId().catch(() => 0)); i++)
    await new Promise((r) => setTimeout(r, 100));
  await rpc("anvil_setCode", [REGISTRY, "0x00"]); // STOP: every execute() succeeds
});
afterAll(() => anvil?.kill());

/** Journal that also asserts the tx is unknown to the node when "submitting" is recorded. */
class CheckingJournal extends MemoryWriteJournal {
  readonly states: string[] = [];
  seenBeforeBroadcast: boolean | undefined;
  override async set(e: WriteEntry) {
    this.states.push(e.state);
    if (e.state === "submitting" && e.txHash)
      this.seenBeforeBroadcast = !!(await pc.getTransaction({ hash: e.txHash }).catch(() => null));
    return super.set(e);
  }
}

const queue = (journal = new CheckingJournal(), spendCapWei = 10n ** 18n, client = pc) =>
  new WriterQueue({
    publicClient: client as never,
    account,
    chain: foundry,
    journal,
    spendCapWei,
    receiptTimeoutMs: 5000,
  });
const del = (q: WriterQueue, i: Hex) =>
  q.run(i, (w) => w.deleteEntity({ entityKey: KEY }, WriterQueue.TX));

describe.skipIf(!ANVIL)("P2-08 WriterQueue (anvil)", () => {
  test("journals the hash before broadcast; legacy tx with gas = max(floor, 2×estimate), fresh nonce", async () => {
    const j = new CheckingJournal();
    const nonce = await pc.getTransactionCount({ address: account.address });
    const r = await del(queue(j), id("w1"));
    expect(j.seenBeforeBroadcast).toBe(false);
    expect(j.states).toEqual(["intent", "submitting", "receipt_confirmed"]);
    const tx = await pc.getTransaction({ hash: r.txHash });
    expect(tx.type).toBe("legacy");
    expect(tx.nonce).toBe(nonce);
    expect(tx.gas).toBe(1_000_000n); // floor for one op; 2 × estimate (~21k) is lower
    expect((await j.get(id("w1")))?.txHash).toBe(r.txHash);
  });

  test("never re-signs: a second run for the same id is refused", async () => {
    const q = queue();
    await del(q, id("w2"));
    await expect(del(q, id("w2"))).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  test("spend cap: refuses to sign, nothing broadcast", async () => {
    const j = new CheckingJournal();
    const nonce = await pc.getTransactionCount({ address: account.address });
    await expect(del(queue(j, 1n), id("w3"))).rejects.toThrow();
    expect(await pc.getTransactionCount({ address: account.address })).toBe(nonce);
    expect(await j.get(id("w3"))).toMatchObject({ state: "failed" });
    expect((await j.get(id("w3")))?.txHash).toBeUndefined();
  });

  test("lost broadcast → reconcile rebroadcasts the SAME signed bytes → confirmed", async () => {
    const j = new CheckingJournal();
    const dropping = {
      ...pc,
      sendRawTransaction: async () => Promise.reject(new Error("network")),
    };
    await expect(del(queue(j, 10n ** 18n, dropping as never), id("w4"))).rejects.toMatchObject({
      code: "LOST_RESPONSE",
    });
    const e = (await j.get(id("w4"))) as WriteEntry;
    expect(e.state).toBe("submitting");
    expect(await pc.getTransaction({ hash: e.txHash as Hex }).catch(() => null)).toBeNull();
    expect(await queue(j).reconcile(id("w4"))).toEqual({ state: "confirmed" });
    expect((await pc.getTransactionReceipt({ hash: e.txHash as Hex })).status).toBe("success");
    expect((await j.get(id("w4")))?.state).toBe("receipt_confirmed");
  });

  test("nonce consumed by another tx → uncertain (ops), nothing re-signed", async () => {
    const j = new CheckingJournal();
    const dropping = {
      ...pc,
      sendRawTransaction: async () => Promise.reject(new Error("network")),
    };
    await expect(del(queue(j, 10n ** 18n, dropping as never), id("w5"))).rejects.toThrow();
    // a different tx takes the same nonce (identical calldata would sign to the identical tx)
    await queue().run(id("w5-other"), (w) =>
      w.deleteEntity({ entityKey: `0x${"cd".repeat(32)}` }, WriterQueue.TX),
    );
    expect(await queue(j).reconcile(id("w5"))).toEqual({ state: "uncertain" });
  });

  test("engine revert in estimation → typed error, unsigned; unknown id reconciles as not_sent", async () => {
    await rpc("anvil_setCode", [REGISTRY, "0x60006000fd"]); // REVERT
    const j = new CheckingJournal();
    await expect(del(queue(j), id("w6"))).rejects.toMatchObject({ code: "REVERTED" });
    expect((await j.get(id("w6")))?.txHash).toBeUndefined();
    await rpc("anvil_setCode", [REGISTRY, "0x00"]);
    expect(await queue().reconcile(id("never"))).toEqual({ state: "not_sent" });
  });
});
