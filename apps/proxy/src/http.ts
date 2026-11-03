// Streamable HTTP downstream (L2 §5.1–5.2). Each downstream MCP session gets its own upstream connection;
// all sessions share one Recorder, i.e. one chain per (agent, lane).
import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { Logger } from "@afr/log";
import type { Recorder } from "@afr/recorder";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createProxy, type Proxy as McpProxy } from "./proxy.js";
import type { Transport } from "./transport.js";

const MAX_BODY = 4 * 1024 * 1024;
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpProxyOptions {
  recorder: Recorder;
  host: string;
  port: number;
  /** Creates the upstream for a new downstream session; gets the initialize request's headers. */
  upstream: (headers: IncomingHttpHeaders) => Transport;
  serverName: string;
  /** Required for non-loopback binds: clients must send `Authorization: Bearer <token>`. */
  authToken?: string;
  log?: Logger;
}

export interface HttpProxy {
  url: string;
  sessions(): number;
  close(): Promise<void>;
}

/** Bind rule (L2 §5.2): non-local binds need a bearer token. */
export function checkBind(host: string, authToken: string | undefined): void {
  if (!LOOPBACK.has(host) && !authToken) {
    throw new Error(
      `refusing to listen on non-loopback ${host} without an auth token (proxy.auth_token_env)`,
    );
  }
}

function authorized(req: IncomingMessage, token: string | undefined): boolean {
  if (!token) return true;
  const got = Buffer.from(req.headers.authorization ?? "");
  const want = Buffer.from(`Bearer ${token}`);
  return got.length === want.length && timingSafeEqual(got, want);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined);
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function reply(res: ServerResponse, status: number, message: string) {
  res
    .writeHead(status, { "content-type": "application/json" })
    .end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }));
}

export async function startHttpProxy(o: HttpProxyOptions): Promise<HttpProxy> {
  checkBind(o.host, o.authToken);
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; proxy: McpProxy }>();

  const server = createServer(async (req, res) => {
    try {
      if (new URL(req.url ?? "/", "http://x").pathname !== "/mcp")
        return reply(res, 404, "not found");
      if (!authorized(req, o.authToken)) return reply(res, 401, "unauthorized");
      const sid = req.headers["mcp-session-id"];
      const existing = typeof sid === "string" ? sessions.get(sid) : undefined;
      if (existing) return await existing.transport.handleRequest(req, res);
      if (req.method !== "POST")
        return reply(res, typeof sid === "string" ? 404 : 400, "no such session");
      const body = await readJson(req);
      if (!isInitializeRequest(body)) return reply(res, 400, "first request must be initialize");

      const port = (server.address() as AddressInfo).port;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        enableDnsRebindingProtection: LOOPBACK.has(o.host),
        allowedHosts: [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`],
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, proxy });
        },
      });
      const proxy = createProxy({
        recorder: o.recorder,
        // SDK classes omit `| undefined` on optional callbacks (exactOptionalPropertyTypes)
        downstream: transport as Transport,
        upstream: o.upstream(req.headers),
        serverName: o.serverName,
        ...(o.log ? { log: o.log } : {}),
        onClose: () => {
          if (transport.sessionId) sessions.delete(transport.sessionId);
        },
      });
      await proxy.start();
      await transport.handleRequest(req, res, body);
    } catch (e) {
      o.log?.warn({ err: (e as Error).name }, "http request failed");
      if (!res.headersSent) reply(res, 400, "bad request");
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port, o.host, resolve);
  });
  const { port } = server.address() as AddressInfo;
  const host = o.host.includes(":") ? `[${o.host}]` : o.host;
  return {
    url: `http://${host}:${port}/mcp`,
    sessions: () => sessions.size,
    async close() {
      await Promise.allSettled([...sessions.values()].map((s) => s.proxy.close()));
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
