// R3/R4 (L2 §15) against an in-process reference server: responses through the proxy deep-equal
// direct responses; notifications, cancellation and server→client requests pass through.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyRecords } from "@afr/core";
import { createCanary, createLogger, memoryDestination } from "@afr/log";
import { parseConfig, Recorder } from "@afr/recorder";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ListRootsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, test } from "vitest";
import { createProxy } from "../src/proxy.js";
// @ts-expect-error plain .mjs fixture
import { buildServer } from "./fixtures/upstream-server.mjs";

const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const env = { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02` };
const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const c of cleanups.splice(0)) await c();
});

function newClient() {
  const client = new Client(
    { name: "test-agent", version: "1.0.0" },
    { capabilities: { roots: {} } },
  );
  client.setRequestHandler(ListRootsRequestSchema, async () => ({
    roots: [{ uri: "file:///tmp", name: "tmp" }],
  }));
  return client;
}

async function direct() {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await buildServer().connect(b);
  const client = newClient();
  await client.connect(a);
  cleanups.push(() => client.close());
  return client;
}

async function proxied(logDest = memoryDestination()) {
  const config = parseConfig(
    {
      version: 1,
      agent: { id: AGENT },
      data_dir: mkdtempSync(join(tmpdir(), "afr-px-")),
      delegation: { mode: "operator_env" },
    },
    {},
  );
  const recorder = await Recorder.start({ config, env, autoRotate: false });
  const [clientSide, proxyDown] = InMemoryTransport.createLinkedPair();
  const [proxyUp, serverSide] = InMemoryTransport.createLinkedPair();
  await buildServer().connect(serverSide);
  const proxy = createProxy({
    recorder,
    downstream: proxyDown,
    upstream: proxyUp,
    serverName: "ref",
    log: createLogger({ name: "t", destination: logDest }),
  });
  await proxy.start();
  const client = newClient();
  await client.connect(clientSide);
  cleanups.push(async () => {
    await client.close();
    await recorder.close().catch(() => {});
  });
  return { client, recorder };
}

const records = (r: Recorder) => [...r.journal.iterate()];

describe("P1-14 proxy", () => {
  test("R3: every response through the proxy deep-equals the direct response", async () => {
    const d = await direct();
    const { client: p, recorder } = await proxied();
    expect(await p.listTools()).toEqual(await d.listTools());
    for (const call of [
      { name: "echo", arguments: { message: "hi" } },
      { name: "fail", arguments: {} },
      { name: "slow", arguments: { steps: 2 } },
      { name: "nope", arguments: {} },
      { name: "echo", arguments: { message: 42 } },
    ]) {
      expect(await p.callTool(call).catch((e) => String(e))).toEqual(
        await d.callTool(call).catch((e) => String(e)),
      );
    }
    const recs = records(recorder);
    const calls = recs.filter((r) => r.type === "tool_call");
    const results = recs.filter((r) => r.type === "tool_result");
    expect(calls.map((r) => r.header.tool?.name)).toEqual(["echo", "fail", "slow", "nope", "echo"]);
    expect(results.map((r) => [r.header.ref_seq, r.header.tool?.is_error])).toEqual(
      calls.map((c, i) => [c.header.seq, i !== 0 && i !== 2]),
    );
    expect(recorder.journal.readBody(calls[0]!.seq).args).toEqual({ message: "hi" });
    expect(recs[1]?.header.meta).toMatchObject({
      event: "mcp_initialize",
      mcp_client: "test-agent/1.0.0",
    });
    expect(
      await verifyRecords(recs.map((r) => ({ header: r.header, sig: r.sig, hash: r.hash }))),
    ).toEqual([]);
  });

  test("R4: progress notifications and server→client requests pass through", async () => {
    const { client } = await proxied();
    const progress: number[] = [];
    const res = await client.callTool({ name: "slow", arguments: { steps: 3 } }, undefined, {
      onprogress: (p) => progress.push(p.progress),
    });
    expect(progress).toEqual([1, 2, 3]);
    expect(res.content).toEqual([{ type: "text", text: "done 3" }]);
    const roots = await client.callTool({ name: "ask_roots", arguments: {} });
    expect(roots.content).toEqual([
      { type: "text", text: JSON.stringify({ roots: [{ uri: "file:///tmp", name: "tmp" }] }) },
    ]);
  });

  test("R4: cancellation records an error result for the pending call", async () => {
    const { client, recorder } = await proxied();
    const ac = new AbortController();
    const p = client.callTool({ name: "slow", arguments: { steps: 50 } }, undefined, {
      signal: ac.signal,
    });
    await new Promise((r) => setTimeout(r, 20));
    ac.abort("user");
    await expect(p).rejects.toThrow();
    const res = records(recorder)
      .filter((r) => r.type === "tool_result")
      .at(-1);
    expect(res?.header).toMatchObject({
      tool: { name: "slow", is_error: true },
      meta: { cancelled: "1" },
    });
  });

  test("R10 (proxy part): tool args and results never reach the logs", async () => {
    const canary = createCanary();
    const dest = memoryDestination();
    const { client } = await proxied(dest);
    await client.callTool({ name: "echo", arguments: { message: canary.value } });
    canary.assertAbsent(dest.output());
  });
});
