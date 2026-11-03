// P1-15: Streamable HTTP on both sides (L2 §5.1–5.2). Responses through the proxy deep-equal direct
// responses; bind and bearer-auth rules hold.
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyRecords } from "@afr/core";
import { parseConfig, Recorder } from "@afr/recorder";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { afterEach, describe, expect, test } from "vitest";
import { checkBind, startHttpProxy } from "../src/http.js";
import { httpUpstream, parseListen } from "../src/transport.js";
// @ts-expect-error plain .mjs fixture
import { buildServer } from "./fixtures/upstream-server.mjs";

const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const env = { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02` };
const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c();
});

/** Reference server over Streamable HTTP; records the Authorization header of each initialize. */
async function httpUpstreamServer() {
  const seenAuth: (string | undefined)[] = [];
  const transports = new Map<string, StreamableHTTPServerTransport>();
  const server = createServer(async (req, res) => {
    const sid = req.headers["mcp-session-id"];
    let t = typeof sid === "string" ? transports.get(sid) : undefined;
    if (!t) {
      seenAuth.push(req.headers.authorization);
      const nt = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: (id) => void transports.set(id, nt),
      });
      await buildServer().connect(nt);
      t = nt;
    }
    await t.handleRequest(req, res);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  cleanups.push(async () => {
    await Promise.allSettled([...transports.values()].map((t) => t.close()));
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, seenAuth };
}

async function connect(url: string, headers?: Record<string, string>) {
  const client = new Client({ name: "test-agent", version: "1.0.0" });
  await client.connect(
    // SDK omits `| undefined` on optional members (exactOptionalPropertyTypes)
    new StreamableHTTPClientTransport(
      new URL(url),
      headers ? { requestInit: { headers } } : {},
    ) as Transport,
  );
  cleanups.push(() => client.close());
  return client;
}

async function proxy(upUrl: string, opts: { authToken?: string; forwardAuth?: boolean } = {}) {
  const config = parseConfig(
    {
      version: 1,
      agent: { id: AGENT },
      data_dir: mkdtempSync(join(tmpdir(), "afr-http-")),
      delegation: { mode: "operator_env" },
    },
    {},
  );
  const recorder = await Recorder.start({ config, env, autoRotate: false });
  const http = await startHttpProxy({
    recorder,
    host: "127.0.0.1",
    port: 0,
    serverName: "ref",
    ...(opts.authToken ? { authToken: opts.authToken } : {}),
    upstream: (h: IncomingHttpHeaders) =>
      httpUpstream(upUrl, opts.forwardAuth ? h.authorization : undefined),
  });
  cleanups.push(async () => {
    await http.close();
    await recorder.close().catch(() => {});
  });
  return { http, recorder };
}

describe("P1-15 Streamable HTTP proxy", () => {
  test("responses through the HTTP proxy deep-equal direct HTTP responses, and are recorded", async () => {
    const up = await httpUpstreamServer();
    const d = await connect(up.url);
    const { http, recorder } = await proxy(up.url);
    const p = await connect(http.url);
    expect(await p.listTools()).toEqual(await d.listTools());
    for (const call of [
      { name: "echo", arguments: { message: "hi" } },
      { name: "fail", arguments: {} },
      { name: "slow", arguments: { steps: 2 } },
    ]) {
      expect(await p.callTool(call)).toEqual(await d.callTool(call));
    }
    const recs = [...recorder.journal.iterate()];
    expect(recs.filter((r) => r.type === "tool_call").map((r) => r.header.tool?.name)).toEqual([
      "echo",
      "fail",
      "slow",
    ]);
    expect(recs.filter((r) => r.type === "tool_result")).toHaveLength(3);
    expect(
      await verifyRecords(recs.map((r) => ({ header: r.header, sig: r.sig, hash: r.hash }))),
    ).toEqual([]);
  });

  test("two downstream sessions share one chain", async () => {
    const up = await httpUpstreamServer();
    const { http, recorder } = await proxy(up.url);
    const [a, b] = await Promise.all([connect(http.url), connect(http.url)]);
    expect(http.sessions()).toBe(2);
    await Promise.all([
      a.callTool({ name: "echo", arguments: { message: "a" } }),
      b.callTool({ name: "echo", arguments: { message: "b" } }),
    ]);
    const recs = [...recorder.journal.iterate()];
    expect(recs.filter((r) => r.type === "tool_call")).toHaveLength(2);
    expect(
      await verifyRecords(recs.map((r) => ({ header: r.header, sig: r.sig, hash: r.hash }))),
    ).toEqual([]);
  });

  test("bearer auth: 401 without the token, works with it; Authorization forwarded only with forward_auth", async () => {
    const up = await httpUpstreamServer();
    const { http } = await proxy(up.url, { authToken: "s3cret" });
    const res = await fetch(http.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: '{"jsonrpc":"2.0","id":1,"method":"ping"}',
    });
    expect(res.status).toBe(401);
    await expect(connect(http.url, { authorization: "Bearer wrong" })).rejects.toThrow();
    const c = await connect(http.url, { authorization: "Bearer s3cret" });
    expect((await c.callTool({ name: "echo", arguments: { message: "x" } })).content).toEqual([
      { type: "text", text: "Echo: x" },
    ]);
    expect(up.seenAuth).toEqual([undefined]);

    const up2 = await httpUpstreamServer();
    const { http: fwd } = await proxy(up2.url, { authToken: "s3cret", forwardAuth: true });
    await connect(fwd.url, { authorization: "Bearer s3cret" });
    expect(up2.seenAuth).toEqual(["Bearer s3cret"]);
  });

  test("404 off /mcp", async () => {
    const up = await httpUpstreamServer();
    const { http } = await proxy(up.url);
    expect((await fetch(http.url.replace("/mcp", "/other"))).status).toBe(404);
  });

  test("bind rule: non-loopback needs a token", () => {
    expect(() => checkBind("0.0.0.0", undefined)).toThrow(/non-loopback/);
    expect(() => checkBind("0.0.0.0", "t")).not.toThrow();
    expect(() => checkBind("127.0.0.1", undefined)).not.toThrow();
    expect(() => checkBind("::1", undefined)).not.toThrow();
  });

  test("parseListen", () => {
    expect(parseListen("127.0.0.1:7801")).toEqual({ host: "127.0.0.1", port: 7801 });
    expect(parseListen("[::1]:7801")).toEqual({ host: "::1", port: 7801 });
    expect(() => parseListen("nope")).toThrow();
  });
});
