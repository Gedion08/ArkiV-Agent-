// P3-10 fr verify agent | prove | keys reader (L7 §5) over the verifier's in-memory fixtures. V6: an RPC
// outage (identity or anchor chain) exits 3, never 2.
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { batchDigest, recoverRecordSigner, verifyBatchProof } from "@afr/core";
import { IDENTITY_REGISTRY_ABI, resolveAgent } from "@afr/identity";
import { decodeFunctionData, type Hex } from "viem";
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

describe("fr agent update-registration", () => {
  const ID = "eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:42";
  const OWNER = `0x${"0a".repeat(20)}` as Hex;
  const WRITER = `0x${"A1".repeat(20)}` as Hex;
  const dataUri = (v: unknown) =>
    `data:application/json;base64,${Buffer.from(JSON.stringify(v)).toString("base64")}`;
  /** An ERC-8004 registry holding one agent whose tokenURI can be "set" (as the operator's tx would). */
  const registry = (uri: string) => {
    const state = { uri };
    const rpc = {
      getChainId: async () => 84532,
      readContract: async ({ functionName }: { functionName: string }) => {
        if (functionName === "ownerOf") return OWNER;
        if (functionName === "tokenURI") return state.uri;
        if (functionName === "getAgentWallet") return OWNER;
        throw new Error(functionName);
      },
    };
    return { state, deps: { identityRpc: rpc as never } satisfies NetDeps };
  };
  const existing = {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "Demo",
    services: [{ name: "MCP", endpoint: "https://agent.example/mcp", version: "2025-06-18" }],
  };

  test("adds the afr service, keeps the rest; the calldata sets a URI that resolves to it", async () => {
    const { state, deps: d } = registry(dataUri(existing));
    const out = join(tmp(), "reg.json");
    const r = await run(["agent", "update-registration", ID, "--out", out, "--writer", WRITER], d);
    expect(r.code).toBe(0);
    const res = JSON.parse(r.out);
    expect(res).toMatchObject({
      file: out,
      operator: OWNER,
      tx: { chainId: 84532, to: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
    });
    const call = decodeFunctionData({ abi: IDENTITY_REGISTRY_ABI, data: res.tx.data });
    expect(call).toMatchObject({ functionName: "setAgentURI", args: [42n, res.uri] });
    const file = JSON.parse(readFileSync(out, "utf8"));
    expect(file.services[0]).toEqual(existing.services[0]);
    expect(file.registrations).toEqual([
      { agentId: 42, agentRegistry: "eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e" },
    ]);

    state.uri = res.uri; // the operator sends the tx
    const after = await resolveAgent(ID, d.identityRpc);
    expect(after.registration).toEqual(file);
    expect(after.afr?.afr).toMatchObject({
      arkiv: { chainId: 7794095, writers: [WRITER.toLowerCase()] },
      anchor: { chainId: 84532, address: "0x976cf1d60b3dc477c70b9e649005f5a12202d341" },
    });
    const show = await run(["agent", "show", ID], d);
    expect(show.out).toContain(`afr       writers ${WRITER.toLowerCase()}`);

    // rerun from the updated file: writers are kept, still one afr entry and one registrations row
    const out2 = join(tmp(), "reg2.json");
    expect((await run(["agent", "update-registration", ID, "--out", out2], d)).code).toBe(0);
    expect(JSON.parse(readFileSync(out2, "utf8"))).toEqual(file);
  });

  test("--uri: the file is hosted by the operator; the calldata points there", async () => {
    const { deps: d } = registry(dataUri(existing));
    const argv = ["agent", "update-registration", ID, "--writer", WRITER, "--out"];
    const r = await run([...argv, join(tmp(), "r.json"), "--uri", "ipfs://bafyexample"], d);
    expect(JSON.parse(r.out).uri).toBe("ipfs://bafyexample");
    for (const bad of [
      [join(tmp(), "r.json"), "--uri", "http://plain.example/r.json"],
      [join(tmp(), "r.json"), "--endpoint", "javascript:alert(1)"],
    ])
      expect((await run([...argv, ...bad], d)).code).toBe(3);
  });

  test("no writers anywhere, an existing --out, or a local: agent → 3", async () => {
    const { deps: d } = registry(dataUri(existing));
    const out = join(tmp(), "r.json");
    expect((await run(["agent", "update-registration", ID, "--out", out], d)).code).toBe(3);
    const argv = ["agent", "update-registration", ID, "--writer", WRITER, "--out", out];
    expect((await run(argv, d)).code).toBe(0);
    expect((await run(argv, d)).code).toBe(3);
    const local = "local:3f1c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a5b";
    expect(
      (await run(["agent", "update-registration", local, "--writer", WRITER, "--out", "x"], d))
        .code,
    ).toBe(3);
  });
});

describe("fr mirror pull + verify --mirror (P3 exit demo)", () => {
  const offline = (a: Agent): NetDeps => {
    const { store: _arkiv, ...rest } = deps(a);
    return rest;
  };

  test("a pulled mirror verifies like Arkiv; one corrupted frame → FAIL at its seq", async () => {
    const a = await agent();
    const file = join(tmp(), "m.jsonl");
    const pulled = await run(["mirror", "pull", a.agentId, "--out", file], deps(a));
    expect(pulled.code).toBe(0);
    expect((await run(["mirror", "pull", a.agentId, "--out", file], deps(a))).code).toBe(3);
    const ok = await run(["verify", "agent", a.agentId, "--mirror", file], offline(a));
    expect(ok.out).toContain("RESULT: PASS");
    expect(ok.code).toBe(0);

    // flip one byte in the middle of the second batch's frame (seq 3…5)
    const lines = readFileSync(file, "utf8").trim().split("\n");
    const i = lines.findIndex((l) => {
      const e = JSON.parse(l);
      return e.schema === "afr.batch.v1" && e.attrs.seq_from === "3";
    });
    const e = JSON.parse(lines[i] as string);
    const mid = 2 + 2 * Math.floor((e.payload.length - 2) / 4);
    const b = (Number.parseInt(e.payload.slice(mid, mid + 2), 16) ^ 1)
      .toString(16)
      .padStart(2, "0");
    e.payload = e.payload.slice(0, mid) + b + e.payload.slice(mid + 2);
    lines[i] = JSON.stringify(e);
    const bad = join(tmp(), "bad.jsonl");
    writeFileSync(bad, `${lines.join("\n")}\n`);
    const r = await run(["verify", "agent", a.agentId, "--mirror", bad, "--json"], offline(a));
    expect(r.code).toBe(2);
    // the flipped byte sits in record 4's signature: FAIL names that record, nothing else
    expect(JSON.parse(r.out).findings).toEqual([
      expect.objectContaining({ code: "RECORD_SIG", severity: "fail", lane: 0, seq: "4" }),
    ]);
  });

  test("a malformed mirror is a usage error, not a FAIL", async () => {
    const a = await agent();
    const file = join(tmp(), "m.jsonl");
    writeFileSync(file, "{not json\n");
    const r = await run(["verify", "agent", a.agentId, "--mirror", file], offline(a));
    expect(r.code).toBe(3);
    expect(r.err).toContain("mirror line 1");
  });
});
