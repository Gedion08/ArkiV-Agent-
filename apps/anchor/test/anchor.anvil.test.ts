// P3-05 on anvil with the real RecorderAnchor: A2 (50 agents × 3 lanes → one anchor tx, every proof
// accepted by verify()), A3 (a rewind is refused and alerted), A5 (crashes around the manifest and the tx
// → the manifest is reused and the root is anchored once). Needs `anvil` (Foundry); CI installs it.
import { typedData } from "@afr/core";
import { decodeCanonical } from "@afr/store";
import { type Hex, type PublicClient, recoverTypedDataAddress } from "viem";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { type AnchorAlert, AnchorService, RECORDER_ANCHOR_ABI } from "../src/index.js";
import {
  ANCHOR_KEY,
  ANVIL,
  anchorChain,
  deployAnchor,
  startAnvil,
  World,
} from "./fixtures/world.js";

let anvil: Awaited<ReturnType<typeof startAnvil>>;
let pc: PublicClient;
beforeAll(async () => {
  if (!ANVIL) return;
  anvil = await startAnvil();
  pc = anvil.pc;
}, 30_000);
afterAll(() => anvil?.stop());

const service = (
  w: World,
  contract: Hex,
  alerts: AnchorAlert[] = [],
  chain = anchorChain(pc, contract),
) =>
  new AnchorService({
    db: w.db,
    store: w.store,
    chain,
    cadenceMs: 0,
    onAlert: (a) => alerts.push(a),
  });
const read = (contract: Hex, functionName: "epochOf" | "rootOf", arg: Hex | bigint) =>
  pc.readContract({
    address: contract,
    abi: RECORDER_ANCHOR_ABI,
    functionName,
    args: [arg],
  } as never) as Promise<unknown>;
const nonce = () => pc.getTransactionCount({ address: ANCHOR_KEY.address });

describe.skipIf(!ANVIL)("P3-05 anchor service (anvil)", () => {
  test("A2: 50 agents × 3 lanes → one anchor tx; every checkpoint's proof passes verify() on-chain", async () => {
    const contract = await deployAnchor(anvil.url, pc);
    const w = new World();
    const latest = new Map<string, { id: string; agentKey: Hex; chainRoot: Hex }>();
    const older: string[] = [];
    for (let agent = 0; agent < 50; agent++)
      for (let lane = 0; lane < 3; lane++) {
        older.push((await w.batch({ agent, lane, seqTo: 9n })).id);
        latest.set(`${agent}:${lane}`, await w.batch({ agent, lane, seqTo: 19n }));
      }
    const before = await nonce();
    const r = await service(w, contract).tick();
    expect(r).toMatchObject({ validated: 300, rejected: 0, anchor: { status: "published" } });
    expect((await nonce()) - before).toBe(1); // one tx for 150 (agent, lane) leaves
    const a = await w.db.anchor(r.anchor?.root as Hex);
    expect(a?.leaves).toHaveLength(150);
    expect(await read(contract, "epochOf", a?.root as Hex)).toBe(a?.epoch);

    for (const { id, agentKey, chainRoot } of latest.values()) {
      const row = w.db.rows.get(id);
      expect(row?.status).toBe("anchored");
      const e = await w.store.get(row?.entity as Hex, "afr.checkpoint.v1");
      expect(e?.attrs).toMatchObject({
        agent_key: agentKey,
        seq_to: 19n,
        chain_root: chainRoot,
        anchor_tx: a?.txHash,
      });
      const p = decodeCanonical(e?.payload as Uint8Array) as {
        statement: Record<string, string | number>;
        sig: Hex;
        proof: Hex[];
        epoch: string;
      };
      const lane = Number(p.statement.lane);
      expect(
        await pc.readContract({
          address: contract,
          abi: RECORDER_ANCHOR_ABI,
          functionName: "verify",
          args: [BigInt(p.epoch), agentKey, lane, 19n, chainRoot, p.proof],
        }),
      ).toBe(true);
      const msg = {
        ...p.statement,
        seqTo: BigInt(p.statement.seqTo as string),
        anchorChainId: BigInt(p.statement.anchorChainId as string),
      };
      const td = typedData(31337, "CheckpointStatement", msg);
      expect(await recoverTypedDataAddress({ ...(td as object), signature: p.sig } as never)).toBe(
        ANCHOR_KEY.address,
      );
    }
    for (const id of older) expect(w.db.rows.get(id)?.status).toBe("superseded");

    // nothing new → no second anchor; confirmation follows the block tags once they pass the anchor block
    await pc.request({ method: "anvil_mine", params: ["0x100"] } as never);
    expect((await service(w, contract).tick()).anchor).toBeUndefined();
    expect((await w.db.anchor(a?.root as Hex))?.status).toBe("finalized");
    expect((await nonce()) - before).toBe(1);
  }, 120_000);

  test("A3: a rewind (lower seq_to than the last anchor) is not anchored; an alert is raised", async () => {
    const contract = await deployAnchor(anvil.url, pc);
    const w = new World();
    const alerts: AnchorAlert[] = [];
    await w.batch({ agent: 1, lane: 0, seqTo: 19n });
    await service(w, contract, alerts).tick();
    const rewind = await w.batch({ agent: 1, lane: 0, seqTo: 14n });
    const before = await nonce();
    const r = await service(w, contract, alerts).tick();
    expect(r.anchor).toBeUndefined();
    expect(await nonce()).toBe(before);
    expect(w.db.rows.get(rewind.id)).toMatchObject({ status: "rejected", reason: "BROKEN_CHAIN" });
    expect(alerts).toEqual([
      expect.objectContaining({ code: "BROKEN_CHAIN", lane: 0, seqTo: 14n }),
    ]);
  }, 60_000);

  test("validation: a forged batch_sig is rejected; an unannounced session key waits, then is rejected", async () => {
    const contract = await deployAnchor(anvil.url, pc);
    const w = new World();
    const alerts: AnchorAlert[] = [];
    const forged = await w.batch({
      agent: 2,
      lane: 0,
      seqTo: 4n,
      signWith: `0x${"77".repeat(32)}`,
    });
    const unknown = await w.batch({ agent: 3, lane: 0, seqTo: 4n, announce: false });
    let now = Date.now();
    const s = new AnchorService({
      db: w.db,
      store: w.store,
      chain: anchorChain(pc, contract),
      cadenceMs: 0,
      now: () => new Date(now),
      onAlert: (a) => alerts.push(a),
    });
    expect(await s.validatePending()).toEqual({ validated: 0, rejected: 1 });
    expect(w.db.rows.get(forged.id)).toMatchObject({ status: "rejected", reason: "BATCH_SIG" });
    expect(w.db.rows.get(unknown.id)?.status).toBe("pending");
    now += 3_600_001;
    expect(await s.validatePending()).toEqual({ validated: 0, rejected: 1 });
    expect(w.db.rows.get(unknown.id)).toMatchObject({
      status: "rejected",
      reason: "UNKNOWN_SESSION_KEY",
    });
    expect(alerts.map((a) => a.detail)).toEqual(["BATCH_SIG", "UNKNOWN_SESSION_KEY"]);
  }, 60_000);

  test("A5: crash after the manifest, then after signing (before broadcast) → manifest reused, one anchor", async () => {
    const contract = await deployAnchor(anvil.url, pc);
    const w = new World();
    for (let agent = 0; agent < 3; agent++) await w.batch({ agent, lane: 0, seqTo: 9n });
    const crash = (at: "sign" | "broadcast") => {
      const c = anchorChain(pc, contract);
      const orig = c[at].bind(c);
      c[at] = (async (...args: never[]) => {
        if (at === "broadcast") throw new Error("crash: process died before broadcast");
        await (orig as (...a: never[]) => Promise<unknown>)(...args); // signs, then dies before the caller journals
        throw new Error("crash: process died after signing");
      }) as never;
      return c;
    };
    const before = await nonce();
    await expect(service(w, contract, [], crash("sign")).tick()).rejects.toThrow(/crash/);
    let open = await w.db.openAnchor();
    expect(open?.status).toBe("manifest");
    const manifestKey = open?.manifestKey;

    w.restartStore(); // a new process: the Arkiv chain and the DB survive, in-memory state doesn't
    await expect(service(w, contract, [], crash("broadcast")).tick()).rejects.toThrow(/crash/);
    open = await w.db.openAnchor();
    expect(open).toMatchObject({ status: "sent", manifestKey });
    expect(await nonce()).toBe(before); // journaled, never broadcast

    w.restartStore();
    const r = await service(w, contract).tick(); // rebroadcasts the journaled bytes
    expect(r.anchor?.status).toBe("published");
    const a = await w.db.anchor(open?.root as Hex);
    expect(a).toMatchObject({ manifestKey, txHash: open?.txHash, epoch: 1n });
    expect((await nonce()) - before).toBe(1);
    const manifests = [];
    for await (const e of w.store.query({
      schema: "afr.anchor.v1",
      where: { anchor_root: { eq: a?.root as Hex } },
    }))
      manifests.push(e);
    expect(manifests).toHaveLength(1);
    expect(manifests[0]?.ref.key).toBe(manifestKey);

    // a later restart finds everything done: no second tx, no duplicate checkpoint entities
    w.restartStore();
    expect((await service(w, contract).tick()).anchor).toBeUndefined();
    expect((await nonce()) - before).toBe(1);
    const cps = [];
    for await (const e of w.store.query({
      schema: "afr.checkpoint.v1",
      where: { anchor_root: { eq: a?.root as Hex } },
    }))
      cps.push(e);
    expect(cps).toHaveLength(3);
  }, 60_000);
});
