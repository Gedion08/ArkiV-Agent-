// P4-03/04 on anvil with the real recorder: W1 (logged tx → matched; raw tx → UNLOGGED_TX after the grace),
// W2 (speed-up → matched by nonce commitment, TX_REPLACED; a never-mined intent → INTENT_NOT_MINED), W4
// (intent notice dropped: the Arkiv batch reconciles it before the grace → no alert; after → LATE_INTENT).
// The recorder's outbox goes to a fake API that writes tx_intents / session_keys like the real routes.
// Needs `anvil` (Foundry); skipped without it.
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentKey } from "@afr/core";
import { parseConfig, Recorder } from "@afr/recorder";
import { MemoryChain, MemoryStore } from "@afr/store";
import { type Hex, keccak256 } from "viem";
import { foundry } from "viem/chains";
import { describe, expect, test } from "vitest";
import { HeadFollower, Matcher, MemoryWatcherDb, reconcileLane, WatchedSet } from "../src/index.js";
import { ANVIL, CHAIN, SINK, useAnvil, WATCHED } from "./fixtures/anvil.js";

const anvil = useAnvil();
const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const AK = agentKey(AGENT);
const AGENT_UUID = "agent-1";
const WRITER = `0x${"a1".repeat(20)}` as Hex;

async function world(o: { dropIntents?: boolean } = {}) {
  const clock = { now: 1_800_000_000_000 };
  const db = new MemoryWatcherDb();
  db.now = () => clock.now;
  db.watches.push({
    chainId: CHAIN,
    address: WATCHED.address,
    entry: { orgId: "org-1", agentId: AGENT_UUID, kind: "eoa" },
  });
  const watched = new WatchedSet(db, CHAIN);
  await watched.reload();
  const follower = new HeadFollower({
    chainId: CHAIN,
    client: anvil.pc,
    db,
    watched,
    startBlock: (await anvil.pc.getBlockNumber()) + 1n,
  });
  const watchKey = new Uint8Array(randomBytes(32));
  const matcher = new Matcher({
    chainId: CHAIN,
    db,
    watchKey: async () => watchKey,
    now: () => clock.now,
  });

  // the API side of the outbox (POST /v1/recorder/intents, /delegations)
  const apiFetch: typeof fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === "/v1/recorder/delegations")
      db.sessionKeys.push({ agentId: AGENT_UUID, lane: body.lane, address: body.session_key });
    if (path === "/v1/recorder/intents" && !o.dropIntents)
      for (const i of body.items)
        db.intents.push({
          agentId: AGENT_UUID,
          lane: i.lane,
          seq: BigInt(i.seq),
          chainId: BigInt(i.chain_id),
          ...(i.tx_commit ? { txCommit: i.tx_commit } : {}),
          nonceCommit: i.nonce_commit,
          receivedAt: clock.now,
        });
    return new Response("{}", { status: 200 });
  };
  const store = new MemoryStore(new MemoryChain(), WRITER);
  const rec = await Recorder.start({
    config: parseConfig(
      {
        version: 1,
        agent: { id: AGENT },
        data_dir: mkdtempSync(join(tmpdir(), "afr-wat-")),
        delegation: { mode: "operator_env" },
        api: { url: "https://api.afr.test" },
      },
      {},
    ),
    env: {
      AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02`,
      AFR_API_KEY: `afr_rk_0123456789abcdef_${"ab".repeat(32)}`,
    },
    autoRotate: false,
    upload: { store, tickMs: 3_600_000, watchKey, apiFetch },
  });
  await rec.delegationReady();

  /** The recorder logs a tx_sign for this tx (as the SDK does before broadcasting). */
  const log = async (hash: Hex, nonce: number | bigint) => {
    rec.capture({
      type: "tx_sign",
      tx: {
        chain_id: CHAIN,
        from: WATCHED.address,
        to: SINK,
        nonce: BigInt(nonce),
        value: 1n,
        tx_hash: hash,
      },
    });
    await rec.flush();
  };
  const sendLogged = async () => {
    const hash = await anvil.send();
    await log(hash, (await anvil.pc.getTransaction({ hash })).nonce);
    return hash;
  };
  const follow = async () => {
    for (let i = 0; i < 20; i++) if ((await follower.tick()).processed === 0) break;
    return anvil.pc.getBlockNumber({ cacheTime: 0 });
  };
  /** Sees new blocks now (stamping seenAt), then lets `advanceMs` pass and sweeps. */
  const sweep = async (advanceMs = 0) => {
    const head = await follow();
    clock.now += advanceMs;
    return matcher.sweep(head);
  };
  const reconcile = () => reconcileLane({ db, store, agentId: AGENT_UUID, agentKey: AK, lane: 0 });
  const match = (h: Hex) => db.matches.get(`${CHAIN}:${h}:${AGENT_UUID}`)?.kind;
  return { db, rec, log, sendLogged, sweep, reconcile, match };
}

describe.skipIf(!ANVIL)("matcher (anvil + recorder)", () => {
  test("W1: a logged tx matches exactly; a raw tx from the same key alerts after the grace", async () => {
    const w = await world();
    const logged = await w.sendLogged();
    expect(await w.sweep()).toEqual([]);
    expect(w.match(logged)).toBe("exact");

    const raw = await anvil.send(); // cast send, bypassing the recorder
    expect(await w.sweep(59_000)).toEqual([]); // still within the grace
    const ev = await w.sweep(2_000);
    expect(ev).toEqual([
      {
        type: "UNLOGGED_TX",
        agentId: AGENT_UUID,
        chainId: CHAIN,
        tx: raw,
        block: expect.any(BigInt),
      },
    ]);
    expect(await w.sweep(60_000)).toEqual([]); // alerted once
    await w.rec.close();
  });

  test("W2: a sped-up tx matches by nonce (TX_REPLACED); an intent never mined is reported after 1 h", async () => {
    const w = await world();
    const wallet = anvil.wallet();
    const nonce = await anvil.pc.getTransactionCount({ address: WATCHED.address });
    const req = await wallet.prepareTransactionRequest({
      account: WATCHED,
      chain: foundry,
      to: SINK,
      value: 1n,
      nonce,
    });
    const original = keccak256(
      await wallet.signTransaction({ ...req, account: WATCHED, chain: foundry }),
    );
    await w.log(original, nonce); // logged, then replaced before it was mined
    const fee = (req.maxFeePerGas ?? 0n) * 2n;
    const replacement = await wallet.sendTransaction({
      account: WATCHED,
      chain: foundry,
      to: SINK,
      value: 1n,
      nonce,
      maxFeePerGas: fee,
      maxPriorityFeePerGas: fee,
    });
    await anvil.pc.waitForTransactionReceipt({ hash: replacement });
    expect(await w.sweep()).toMatchObject([{ type: "TX_REPLACED", tx: replacement }]);
    expect(w.match(replacement)).toBe("replacement");

    await w.log(`0x${"5a".repeat(32)}`, 999n); // signed, never broadcast
    const later = await w.sweep(3_601_000);
    // the replaced intent matched (by nonce): only the dropped one is reported
    expect(later).toEqual([
      {
        type: "INTENT_NOT_MINED",
        agentId: AGENT_UUID,
        chainId: CHAIN,
        lane: 0,
        seq: expect.any(BigInt),
      },
    ]);
    expect(await w.sweep(60_000)).toEqual([]);
    await w.rec.close();
  });

  test("W4: a dropped intent notice is recovered from the Arkiv batch; late → alert, then LATE_INTENT", async () => {
    const w = await world({ dropIntents: true });
    const a = await w.sendLogged();
    expect(w.db.intents).toEqual([]); // the notice never reached the API

    // only batches signed by a registered session key count
    const keys = w.db.sessionKeys.splice(0);
    expect(await w.reconcile()).toBe(0);
    w.db.sessionKeys.push(...keys);

    // 40 s later the batch is reconciled: matched, no alert
    expect(await w.reconcile()).toBeGreaterThan(0);
    expect(await w.sweep(40_000)).toEqual([]);
    expect(w.match(a)).toBe("exact");

    // 90 s: the alert fires at the grace, the batch arrives after it and resolves it
    const b = await w.sendLogged();
    expect(await w.sweep(61_000)).toMatchObject([{ type: "UNLOGGED_TX", tx: b }]);
    expect(await w.reconcile()).toBeGreaterThan(0);
    expect(await w.sweep(29_000)).toMatchObject([{ type: "LATE_INTENT", tx: b }]);
    expect(w.match(b)).toBe("late_intent");
    expect(await w.sweep(60_000)).toEqual([]);
    await w.rec.close();
  });
});
