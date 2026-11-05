// P4-03/04 on anvil with the real recorder: W1 (logged tx → matched; raw tx → UNLOGGED_TX after the grace),
// W2 (speed-up → matched by nonce commitment, TX_REPLACED; a never-mined intent → INTENT_NOT_MINED), W4
// (intent notice dropped: the Arkiv batch reconciles it before the grace → no alert; after → LATE_INTENT).
// Also: per-agent grace, a rotated watch key (the previous one still matches), and reconciliation refusing
// batches whose delegation isn't the operator's or doesn't cover the batch's write time.
// The recorder's outbox goes to a fake API that writes tx_intents / session_keys like the real routes.
// Needs `anvil` (Foundry); skipped without it.
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, Recorder } from "@afr/recorder";
import { MemoryChain, MemoryStore } from "@afr/store";
import { staticIdentityReader } from "@afr/verifier";
import { HeadFollower, Matcher, MemoryWatcherDb, reconcileLane, WatchedSet } from "@afr/watcher";
import { type Hex, keccak256 } from "viem";
import { foundry } from "viem/chains";
import { describe, expect, test } from "vitest";
import {
  ANVIL,
  CHAIN,
  SINK,
  useAnvil,
  WATCHED,
} from "../../../apps/watcher/test/fixtures/anvil.js";

const anvil = useAnvil();
const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const AGENT_UUID = "agent-1";
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const OPERATOR_KEY = `0x${"00".repeat(31)}02` as const;
const OPERATOR = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf" as Hex; // address of OPERATOR_KEY

interface WorldOptions {
  dropIntents?: boolean;
  /** Who the identity reader says the operator is (default: the key that signs the delegations). */
  operator?: Hex;
  /** Shifts Arkiv's clock against the delegation's (real-time) validity window. */
  arkivOffsetS?: number;
}

async function world(o: WorldOptions = {}) {
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
  const keys = { current: watchKey, previous: undefined as Uint8Array | undefined };
  const matcher = new Matcher({
    chainId: CHAIN,
    db,
    // copies: the matcher zeroes keys it forgets, and the recorder holds the original
    watchKeys: async () =>
      [keys.current, ...(keys.previous ? [keys.previous] : [])].map((k) => k.slice()),
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
  const chain = new MemoryChain();
  // the memory chain's clock starts in the past: line it up with real time (the delegation's), plus the offset
  chain.block = BigInt(
    Math.floor((Date.now() / 1000 + (o.arkivOffsetS ?? 0) - chain.genesisTs) / 2),
  );
  const store = new MemoryStore(chain, WRITER);
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
      AFR_OPERATOR_KEY: OPERATOR_KEY,
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
  const identity = staticIdentityReader(o.operator ?? OPERATOR);
  const reconcile = () =>
    reconcileLane({ db, store, identity, agentId: AGENT_UUID, agent: AGENT, lane: 0 });
  const match = (h: Hex) => db.matches.get(`${CHAIN}:${h}:${AGENT_UUID}`)?.kind;
  return { db, rec, keys, matcher, log, sendLogged, sweep, reconcile, match };
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
    const nonce = await anvil.pc.getTransactionCount({ address: WATCHED.address });
    // signed locally, never sent (explicit fields: viem's request inference overflows tsc's stack here)
    const fees = await anvil.pc.estimateFeesPerGas();
    const tx = {
      chainId: foundry.id,
      type: "eip1559",
      to: SINK,
      value: 1n,
      nonce,
      gas: 21_000n,
    } as const;
    const original = keccak256(await WATCHED.signTransaction({ ...tx, ...fees }));
    await w.log(original, nonce); // logged, then replaced before it was mined
    const fee = fees.maxFeePerGas * 2n;
    const replacement = await anvil.pc.sendRawTransaction({
      serializedTransaction: await WATCHED.signTransaction({
        ...tx,
        maxFeePerGas: fee,
        maxPriorityFeePerGas: fee,
      }),
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

  test("reconciliation needs the operator's delegation, valid when the batch was written", async () => {
    for (const o of [
      { operator: `0x${"0d".repeat(20)}` as Hex }, // the delegation isn't signed by the agent's operator
      { arkivOffsetS: 2 * 86_400 }, // written after notAfter + 1 h (the session key lives 24 h)
      { arkivOffsetS: -86_400 }, // written before notBefore
    ]) {
      const w = await world({ ...o, dropIntents: true });
      const a = await w.sendLogged();
      expect(await w.reconcile()).toBe(0);
      expect(await w.sweep(61_000)).toMatchObject([{ type: "UNLOGGED_TX", tx: a }]);
      await w.rec.close();
    }
  }, 20_000); // three recorders

  test("per-agent grace; after a rotation intents under the previous key still match", async () => {
    const w = await world();
    w.db.graceS.set(AGENT_UUID, 15);
    const raw = await anvil.send();
    expect(await w.sweep(14_000)).toEqual([]);
    expect(await w.sweep(2_000)).toMatchObject([{ type: "UNLOGGED_TX", tx: raw }]);

    // rotate: the watcher gets the new key first, the recorder still commits under the old one
    w.keys.previous = w.keys.current;
    w.keys.current = new Uint8Array(randomBytes(32));
    w.matcher.forgetKeys(AGENT_UUID);
    const logged = await w.sendLogged();
    expect(await w.sweep()).toEqual([]);
    expect(w.match(logged)).toBe("exact");
    await w.rec.close();
  });
});
