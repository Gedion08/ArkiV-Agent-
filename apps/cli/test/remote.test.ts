// P3-10 fr verify agent | prove | keys reader (L7 §5) over the verifier's in-memory fixtures. V6: an RPC
// outage (identity or anchor chain) exits 3, never 2.
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { batchDigest, recoverRecordSigner, verifyBatchProof } from "@afr/core";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, test } from "vitest";
import {
  Agent,
  ANCHOR_CONTRACTS,
  T0,
  VECTOR_SK,
} from "../../../packages/verifier/test/fixtures/agent.js";
import { main, type NetDeps } from "../src/index.js";

const SK2 = `0x${"00".repeat(31)}02` as Hex;
const NOW = new Date(Number(T0 + 3600n) * 1000);
const tmp = () => mkdtempSync(join(tmpdir(), "afr-fr-"));

async function agent(n = 2) {
  const a = new Agent();
  await a.delegate(VECTOR_SK);
  await a.profile();
  for (let i = 0; i < n; i++) await a.batch(0, 3, VECTOR_SK);
  if (n) await a.anchor([0]);
  return a;
}

const deps = (a: Agent, o: Partial<NetDeps> = {}): NetDeps => ({
  store: a.store,
  identity: a.identity,
  anchors: a.anchors,
  verify: { anchorContracts: ANCHOR_CONTRACTS, now: () => NOW },
  ...o,
});

async function run(argv: string[], d: NetDeps, env: NodeJS.ProcessEnv = {}) {
  let out = "";
  let err = "";
  const code = await main(
    argv,
    env,
    (s) => {
      out += s;
    },
    (s) => {
      err += s;
    },
    d,
  );
  return { code, out, err };
}

describe("fr verify agent", () => {
  test("PASS → 0, human output ends with RESULT", async () => {
    const a = await agent();
    const r = await run(["verify", "agent", a.agentId], deps(a));
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/lane 0 +6 records · 2 batches · seq 0…5/);
    expect(r.out.trim().split("\n").at(-1)).toMatch(/^RESULT: PASS \(structural\)/);
  });

  test("--json is the L7 §4 report", async () => {
    const a = await agent();
    const r = await run(["verify", "agent", a.agentId, "--json"], deps(a));
    expect(JSON.parse(r.out)).toMatchObject({
      format: "afr/1",
      agent_id: a.agentId,
      result: "PASS",
    });
  });

  test("warnings → 1, or 2 with --strict", async () => {
    const a = await agent();
    await a.delegate(SK2, { by: privateKeyToAccount(`0x${"0d".repeat(32)}`) }); // not the operator
    const argv = ["verify", "agent", a.agentId];
    const r = await run(argv, deps(a));
    expect(r.code).toBe(1);
    expect(r.out).toContain("⚠ DELEGATION_BAD_SIG");
    expect((await run([...argv, "--strict"], deps(a))).code).toBe(2);
  });

  test("FAIL → 2 (equivocation)", async () => {
    const a = await agent(1);
    const before = { ...(a.tip.get(0) as { seq: bigint; prevHash: Hex; chainRoot: Hex }) };
    await a.batch(0, 3, VECTOR_SK);
    await a.delegate(SK2);
    a.tip.set(0, before);
    await a.batch(0, 3, SK2);
    const r = await run(["verify", "agent", a.agentId], deps(a));
    expect(r.code).toBe(2);
    expect(r.out).toContain("✖ EQUIVOCATION");
  });

  test("V6: identity or anchor RPC down → 3, never 2; no message text leaks", async () => {
    const a = await agent();
    const down = () => {
      throw Object.assign(new Error("fetch failed https://rpc.example/KEY"), {
        code: "ECONNREFUSED",
      });
    };
    for (const d of [
      deps(a, { identity: { resolve: down, isOperatorSig: down } }),
      deps(a, { anchors: { anchor: down, isRecorder: down } }),
    ]) {
      const r = await run(["verify", "agent", a.agentId], d);
      expect(r.code).toBe(3);
      expect(r.err).toBe("infrastructure error ECONNREFUSED\n");
      expect(r.out).toBe("");
    }
  });

  test("usage errors → 3", async () => {
    const a = await agent(0);
    expect((await run(["verify", "agent"], deps(a))).code).toBe(3);
    expect((await run(["verify", "agent", "nope"], deps(a))).code).toBe(3);
    expect((await run(["verify", "agent", a.agentId, "--bogus"], deps(a))).code).toBe(3);
    // no store injected and no ARKIV_ACCESS_KEY
    const r = await run(["verify", "agent", a.agentId], { identity: a.identity });
    expect([r.code, r.err.split("\n")[0]]).toEqual([
      3,
      "ARKIV_ACCESS_KEY is required to read Arkiv",
    ]);
  });
});

describe("fr prove", () => {
  test("writes a self-consistent proof and refuses to overwrite", async () => {
    const a = await agent();
    const out = join(tmp(), "proof.json");
    const r = await run(["prove", a.agentId, "4", "--out", out], deps(a));
    expect(r.code).toBe(0);
    const p = JSON.parse(readFileSync(out, "utf8"));
    expect(p).toMatchObject({ format: "afr-proof/1", agent_id: a.agentId, lane: 0, seq: "4" });
    expect(
      verifyBatchProof(p.batch.batch_root, { seq: 4n, hash: p.record.hash }, p.merkle_proof),
    ).toBe(true);
    expect(await recoverRecordSigner(p.record.hash, p.record.sig)).toBe(
      p.record.session_key.toLowerCase(),
    );
    const signer = await recoverRecordSigner(
      batchDigest({
        agentKey: a.ak,
        lane: 0,
        seqFrom: BigInt(p.batch.seq_from),
        seqTo: BigInt(p.batch.seq_to),
        batchRoot: p.batch.batch_root,
        prevChainRoot: p.batch.prev_chain_root,
        chainRoot: p.batch.chain_root,
        payloadCtHash: p.batch.payload_ct_hash,
      }),
      p.batch.batch_sig,
    );
    expect(p.batch.session_keys.map((k: string) => k.toLowerCase())).toContain(signer);
    expect(BigInt(p.checkpoint.statement.seqTo)).toBeGreaterThanOrEqual(4n);
    expect((await run(["prove", a.agentId, "4", "--out", out], deps(a))).code).toBe(3);
  });

  test("an unknown seq → 3", async () => {
    const a = await agent();
    const r = await run(["prove", a.agentId, "99", "--out", join(tmp(), "p.json")], deps(a));
    expect(r.code).toBe(3);
  });
});

describe("fr keys reader", () => {
  test("new writes a 0600 .afrkey; show prints its public key", async () => {
    const file = join(tmp(), "r.afrkey");
    const d: NetDeps = { passphrase: async () => "correct horse battery" };
    const r = await run(["keys", "reader", "new", "--out", file], d);
    expect(r.code).toBe(0);
    const pub = JSON.parse(r.out).reader;
    expect(pub).toMatch(/^0x[0-9a-f]{64}$/);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, "utf8")).not.toContain("correct horse");
    expect((await run(["keys", "reader", "show", file], d)).out).toBe(`${pub}\n`);
    expect((await run(["keys", "reader", "new", "--out", file], d)).code).toBe(3);
  }, 30_000);

  test("short passphrases are refused", async () => {
    const r = await run(["keys", "reader", "new", "--out", join(tmp(), "k.afrkey")], {
      passphrase: async () => "short",
    });
    expect(r.code).toBe(3);
  });
});
