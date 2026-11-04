// P2-12: delegations (and the agent profile) are published before any batch that needs them (L2 §9).
import { agentKey, keccakJcs, verifyTyped } from "@afr/core";
import { decodeCanonical, decodeFrame, MemoryChain, MemoryStore } from "@afr/store";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, test } from "vitest";
import { identityChainId, Recorder } from "../src/index.js";
import { AGENT, env, OPERATOR_ADDR, OPERATOR_KEY, ready, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const CHAIN = identityChainId(AGENT);
const R1 = `0x${"01".repeat(32)}` as Hex;

const rows = (chain: MemoryChain) => [...chain.rows.values()];
const payloadOf = (chain: MemoryChain, schema: string) =>
  rows(chain)
    .filter((r) => r.schema === schema)
    .map((r) => decodeCanonical(r.payload) as Record<string, unknown>);
const asTyped = (m: Record<string, unknown>) => ({
  ...m,
  notBefore: BigInt(m.notBefore as string),
  notAfter: BigInt(m.notAfter as string),
  nonce: BigInt(m.nonce as string),
});

describe("P2-12 delegations + agent profile", () => {
  test("a batch is never submitted before its delegation; the published delegation verifies", async () => {
    const chain = new MemoryChain();
    const store = new MemoryStore(chain, WRITER);
    let sign: (() => void) | undefined;
    const op = privateKeyToAccount(OPERATOR_KEY);
    const rec = await Recorder.start({
      config: tmpConfig({ delegation: { mode: "interactive" } }),
      env: {},
      autoRotate: false,
      // a human who signs only when told to
      requestSignature: (typed) =>
        new Promise((resolve) => {
          sign = () => op.signTypedData(typed as never).then(resolve);
        }),
      upload: { store, tickMs: 3_600_000 },
    });
    await rec.flush();
    await rec.flush();
    expect(rows(chain)).toEqual([]); // no delegation yet, and no operator key for a profile
    expect(rec.status().batches).toEqual({ prepared: 1 });

    sign?.();
    await rec.delegationReady();
    await rec.flush();
    expect(rows(chain).map((r) => r.schema)).toEqual(["afr.delegation.v1", "afr.batch.v1"]);
    const [d] = rows(chain);
    const sk = rec.status().sessionKey.toLowerCase() as Hex;
    expect(d).toMatchObject({ readonly: true, permissionlessExtension: true });
    expect(d?.attrs).toMatchObject({
      agent_key: AK,
      lane: 0n,
      session_key: sk,
      delegator: OPERATOR_ADDR,
    });
    const [stmt] = payloadOf(chain, "afr.delegation.v1");
    const message = stmt?.message as Record<string, unknown>;
    expect(message.sessionKey).toBe(rec.status().sessionKey);
    expect(
      await verifyTyped(CHAIN, "Delegation", asTyped(message), stmt?.sig as Hex, OPERATOR_ADDR),
    ).toBe(true);
    expect(rec.journal.sessionKey(sk)?.delegationEntity).toBe([...chain.rows.keys()][0]);
    await rec.close();
  });

  test("a crashed session's delegation is published from the journal before the batch listing its key", async () => {
    const config = tmpConfig();
    const first = await ready(Recorder.start({ config, env, autoRotate: false })); // journal only
    first.capture({ type: "note", body: { args: {} } });
    const dead = first.status().sessionKey.toLowerCase();
    first.journal.close(); // crash
    const chain = new MemoryChain();
    const rec = await ready(
      Recorder.start({
        config,
        env,
        autoRotate: false,
        upload: { store: new MemoryStore(chain, WRITER), tickMs: 3_600_000 },
      }),
    );
    await rec.flush();
    const kinds = rows(chain).map((r) => r.schema);
    const batch = rows(chain).find((r) => r.schema === "afr.batch.v1");
    const delegated = rows(chain)
      .filter((r) => r.schema === "afr.delegation.v1")
      .map((r) => r.attrs.session_key);
    expect(delegated).toEqual([dead, rec.status().sessionKey.toLowerCase()]);
    expect(kinds.lastIndexOf("afr.delegation.v1")).toBeLessThan(kinds.indexOf("afr.batch.v1"));
    expect(decodeFrame(batch?.payload as Uint8Array).pub.session_keys).toEqual(delegated);
    await rec.close();
  });

  test("agent profile: operator-signed, versioned on change, not republished when unchanged", async () => {
    const config = tmpConfig({ encryption: { readers: [R1] } });
    const chain = new MemoryChain();
    const start = () =>
      ready(
        Recorder.start({
          config,
          env,
          autoRotate: false,
          upload: {
            store: new MemoryStore(chain, WRITER),
            tickMs: 3_600_000,
            sealKeygrant: () => ({ enc: new Uint8Array(32), ct: new Uint8Array(48) }),
          },
        }),
      );
    const rec = await start();
    await rec.flush();
    const [p1] = payloadOf(chain, "afr.agent.v1");
    const profile = p1?.profile as Record<string, unknown>;
    expect(profile).toMatchObject({
      agentKey: AK,
      privacyLevel: 0,
      retentionDays: 365,
      version: "1",
    });
    expect(profile.readersHash).toBe(keccakJcs([R1]));
    expect(p1).toMatchObject({ writers: [WRITER], readers: [R1] });
    expect(
      await verifyTyped(
        CHAIN,
        "AgentProfile",
        { ...profile, version: 1n },
        p1?.sig as Hex,
        OPERATOR_ADDR,
      ),
    ).toBe(true);
    const row = rows(chain).find((r) => r.schema === "afr.agent.v1");
    expect(row).toMatchObject({ readonly: false, permissionlessExtension: true, owner: WRITER });
    expect(row?.attrs).toMatchObject({
      agent_key: AK,
      agent_id: AGENT,
      operator: OPERATOR_ADDR,
      version: 1n,
    });
    await rec.close();

    const again = await start(); // unchanged: no new version
    await again.flush();
    expect(payloadOf(chain, "afr.agent.v1")).toHaveLength(1);
    again.setReaders([]);
    again.capture({ type: "note", body: { args: {} } });
    await again.flush();
    const versions = payloadOf(chain, "afr.agent.v1").map(
      (p) => (p.profile as { version: string }).version,
    );
    expect(versions).toEqual(["1", "2"]);
    await again.close();
  });
});
