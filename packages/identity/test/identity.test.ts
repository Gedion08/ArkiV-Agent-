// P3-04 unit tests: registration file, agent URIs, block-by-time search and calldata. No network.
import { decodeFunctionData, type Hex } from "viem";
import { describe, expect, test } from "vitest";
import {
  type AfrService,
  blockAtOrBefore,
  buildRegistrationWithAfr,
  encodeRegister,
  encodeSetAgentURI,
  encodeValidationResponse,
  fetchUriJson,
  findAfrService,
  IDENTITY_REGISTRY_ABI,
  type IdentityClient,
  operatorAt,
  parseRegistration,
  REGISTRATION_TYPE,
  VALIDATION_REGISTRY_ABI,
} from "../src/index.js";

const AFR: AfrService = {
  name: "afr",
  endpoint: "https://verify.afr.dev/agents/x",
  version: "afr/1",
  afr: {
    agentKey: `0x${"ab".repeat(32)}`,
    arkiv: { chainId: 7794095, schemas: ["afr.batch.v1"], writers: [`0x${"a1".repeat(20)}`] },
    anchor: {
      chainId: 84532,
      address: "0x976cf1d60b3dc477c70b9e649005f5a12202d341",
      fromBlock: 54399317,
    },
  },
};
const code = (p: Promise<unknown>) => expect(p).rejects.toMatchObject({ code: expect.any(String) });
const rejectsWith = (p: Promise<unknown>, c: string) =>
  expect(p).rejects.toMatchObject({ code: c });

describe("registration file", () => {
  test("reads services, or endpoints from older drafts; finds the afr entry", () => {
    const old = parseRegistration({
      type: "x",
      endpoints: [{ name: "MCP", endpoint: "https://m" }, AFR],
    });
    expect(old.services).toHaveLength(2);
    expect("endpoints" in old).toBe(false);
    expect(findAfrService(old)).toEqual(AFR);
    expect(findAfrService(parseRegistration({ type: "x", services: [] }))).toBeUndefined();
  });

  test("rejects malformed files and afr entries", () => {
    for (const bad of [
      null,
      [],
      "x",
      { services: [] },
      { type: "x" },
      { type: "x", services: [{ name: 1 }] },
    ])
      expect(() => parseRegistration(bad)).toThrow(
        expect.objectContaining({ code: "REGISTRATION_INVALID" }),
      );
    const withAfr = (afr: unknown, version = "afr/1") =>
      parseRegistration({ type: "x", services: [{ name: "afr", endpoint: "e", version, afr }] });
    for (const reg of [
      withAfr(AFR.afr, "afr/2"),
      withAfr({ ...AFR.afr, agentKey: `0x${"AB".repeat(32)}` }),
      withAfr({ ...AFR.afr, arkiv: { ...AFR.afr.arkiv, writers: ["nope"] } }),
      withAfr({ ...AFR.afr, anchor: { chainId: 1, address: "0x1", fromBlock: 0 } }),
      withAfr({ ...AFR.afr, verifier: 3 }),
    ])
      expect(() => findAfrService(reg)).toThrow(
        expect.objectContaining({ code: "AFR_SERVICE_INVALID" }),
      );
  });

  test("buildRegistrationWithAfr replaces any afr entry, keeps the rest, never mutates", () => {
    const existing = parseRegistration({
      type: "old",
      name: "Agent",
      endpoints: [
        { name: "MCP", endpoint: "https://m" },
        { ...AFR, endpoint: "https://stale" },
      ],
    });
    const before = structuredClone(existing);
    const next = buildRegistrationWithAfr(existing, AFR);
    expect(existing).toEqual(before);
    expect(next.type).toBe(REGISTRATION_TYPE);
    expect(next.name).toBe("Agent");
    expect(next.services.map((s) => s.name)).toEqual(["MCP", "afr"]);
    expect(findAfrService(next)).toEqual(AFR);
  });
});

describe("agent URI", () => {
  const json = JSON.stringify({ type: REGISTRATION_TYPE, services: [] });
  test("data: base64 and plain", async () => {
    expect(await fetchUriJson(`data:application/json;base64,${btoa(json)}`)).toEqual(
      JSON.parse(json),
    );
    expect(await fetchUriJson(`data:application/json,${encodeURIComponent(json)}`)).toEqual(
      JSON.parse(json),
    );
  });

  test("https through the injected fetch, ipfs through a gateway; http and bare ipfs refused", async () => {
    const urls: string[] = [];
    const fetch = (async (u: string) => {
      urls.push(u);
      return new Response(json);
    }) as typeof globalThis.fetch;
    await fetchUriJson("https://a.example/reg.json", { fetch });
    await fetchUriJson("ipfs://bafyabc", { fetch, ipfsGateway: "https://gw.example/" });
    expect(urls).toEqual(["https://a.example/reg.json", "https://gw.example/ipfs/bafyabc"]);
    await rejectsWith(fetchUriJson("http://a.example/x", { fetch }), "URI_UNSUPPORTED");
    await rejectsWith(fetchUriJson("ipfs://bafyabc", { fetch }), "URI_UNSUPPORTED");
    await rejectsWith(fetchUriJson("file:///etc/passwd", { fetch }), "URI_UNSUPPORTED");
  });

  test("size cap, non-JSON and fetch failures", async () => {
    const big = (async () => new Response("x".repeat(70_000))) as typeof globalThis.fetch;
    await rejectsWith(fetchUriJson("https://a.example", { fetch: big }), "URI_TOO_LARGE");
    await rejectsWith(fetchUriJson(`data:application/json,${"1".repeat(70_000)}`), "URI_TOO_LARGE");
    await rejectsWith(fetchUriJson("data:application/json,{nope"), "REGISTRATION_INVALID");
    await rejectsWith(fetchUriJson("data:application/json;base64,%%%"), "REGISTRATION_INVALID");
    const down = (async () => new Response("", { status: 404 })) as typeof globalThis.fetch;
    await rejectsWith(fetchUriJson("https://a.example", { fetch: down }), "URI_FETCH_FAILED");
    const boom = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof globalThis.fetch;
    await code(fetchUriJson("https://a.example", { fetch: boom }));
  });
});

describe("blockAtOrBefore", () => {
  /** Irregular block times (1 s, 2 s, then 30 s gaps) like a chain that changed its block time. */
  function chain(n: number, earliest = 0) {
    const ts: bigint[] = [];
    let t = 1_000_000n;
    for (let i = 0; i < n; i++) {
      ts.push(t);
      t += i < n / 3 ? 1n : i < (2 * n) / 3 ? 2n : 30n;
    }
    let calls = 0;
    const rpc = {
      getBlock: async (a: { blockTag?: string; blockNumber?: bigint }) => {
        calls++;
        const num = a.blockTag === "latest" ? BigInt(n - 1) : (a.blockNumber as bigint);
        if (num < BigInt(earliest)) throw new Error("pruned history unavailable");
        return { number: num, timestamp: ts[Number(num)] as bigint };
      },
    } as unknown as IdentityClient;
    return { ts, rpc, calls: () => calls };
  }

  test("returns the last block with timestamp ≤ ts, everywhere on the chain", async () => {
    const { ts, rpc } = chain(3000);
    const want = (t: bigint) => {
      let b = -1;
      for (let i = 0; i < ts.length; i++) if ((ts[i] as bigint) <= t) b = i;
      return BigInt(b);
    };
    const first = ts[0] as bigint;
    const last = ts.at(-1) as bigint;
    for (const t of [
      first,
      first + 7n,
      ts[999] as bigint,
      (ts[1500] as bigint) + 1n,
      last - 1n,
      last,
      last + 99n,
    ])
      expect(await blockAtOrBefore(rpc, t)).toBe(want(t));
    await rejectsWith(blockAtOrBefore(rpc, first - 1n), "BEFORE_GENESIS");
  });

  test("stays near the target: recent lookups work when old headers are pruned", async () => {
    const c = chain(3000, 2500);
    expect(await blockAtOrBefore(c.rpc, c.ts[2900] as bigint)).toBe(2900n);
    expect(c.calls()).toBeLessThan(40);
    await rejectsWith(blockAtOrBefore(c.rpc, c.ts[100] as bigint), "RPC_HISTORY_UNAVAILABLE");
  });
});

describe("calldata", () => {
  test("register, setAgentURI and validationResponse round-trip through the ABIs", () => {
    const meta = [{ metadataKey: "k", metadataValue: "0x01" as Hex }];
    expect(
      decodeFunctionData({ abi: IDENTITY_REGISTRY_ABI, data: encodeRegister("ipfs://x") }).args,
    ).toEqual(["ipfs://x"]);
    expect(
      decodeFunctionData({ abi: IDENTITY_REGISTRY_ABI, data: encodeRegister("ipfs://x", meta) })
        .args,
    ).toEqual(["ipfs://x", meta]);
    const set = decodeFunctionData({
      abi: IDENTITY_REGISTRY_ABI,
      data: encodeSetAgentURI(7n, "https://r"),
    });
    expect([set.functionName, set.args]).toEqual(["setAgentURI", [7n, "https://r"]]);
    const v = {
      requestHash: `0x${"11".repeat(32)}` as Hex,
      response: 100,
      responseURI: "ipfs://att",
      responseHash: `0x${"22".repeat(32)}` as Hex,
      tag: "afr",
    };
    expect(
      decodeFunctionData({ abi: VALIDATION_REGISTRY_ABI, data: encodeValidationResponse(v) }).args,
    ).toEqual([v.requestHash, 100, v.responseURI, v.responseHash, "afr"]);
    for (const response of [-1, 101, 1.5])
      expect(() => encodeValidationResponse({ ...v, response })).toThrow(
        expect.objectContaining({ code: "VALIDATION_RESPONSE_RANGE" }),
      );
  });
});

test("an rpc on another chain is refused", async () => {
  const other = { getChainId: async () => 8453 } as unknown as IdentityClient;
  await rejectsWith(
    operatorAt("eip155:84532:0x8004a818bfb912233c491871b3d84c89a494bd9e:1", 0n, other),
    "CHAIN_MISMATCH",
  );
});
