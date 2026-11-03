// JSON-RPC message-level MCP proxy (L2 §5.2). Forwards every message unchanged; records tool calls.
import type { AfrError } from "@afr/core";
import type { Logger } from "@afr/log";
import type { CaptureEvent, Recorder } from "@afr/recorder";
import {
  isJSONRPCErrorResponse,
  isJSONRPCNotification,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "./transport.js";

interface Pending {
  seq: bigint;
  name: string;
  started: number;
}

export interface ProxyOptions {
  recorder: Recorder;
  downstream: Transport;
  upstream: Transport;
  /** MCP server name from config (ToolInfo.server). */
  serverName: string;
  log?: Logger;
  now?: () => number;
  onClose?: () => void;
}

export interface Proxy {
  start(): Promise<void>;
  close(): Promise<void>;
}

const idKey = (id: string | number) => `${typeof id}:${id}`;

export function createProxy(o: ProxyOptions): Proxy {
  const now = o.now ?? Date.now;
  const pending = new Map<string, Pending>();
  let closed = false;

  // Fail-open: recording problems are logged (codes only) and never block or alter traffic.
  const record = (ev: CaptureEvent): bigint | undefined => {
    try {
      return o.recorder.capture(ev).seq;
    } catch (e) {
      o.log?.error(
        { code: (e as AfrError).code ?? "CAPTURE_FAILED", type: ev.type },
        "capture failed; forwarding anyway",
      );
      return undefined;
    }
  };

  const finish = (
    key: string,
    result: unknown,
    isError: boolean,
    meta?: Record<string, string>,
  ) => {
    const p = pending.get(key);
    if (!p) return;
    pending.delete(key);
    record({
      type: "tool_result",
      refSeq: p.seq,
      tool: {
        server: o.serverName,
        name: p.name,
        is_error: isError,
        duration_ms: String(Math.max(0, now() - p.started)),
      },
      body: { result },
      ...(meta ? { meta } : {}),
    });
  };

  const send = (t: Transport, msg: JSONRPCMessage, dir: string) => {
    t.send(msg).catch((e: Error) => o.log?.error({ dir, err: e.name }, "forward failed"));
  };

  o.downstream.onmessage = (msg) => {
    if (isJSONRPCRequest(msg)) {
      if (msg.method === "tools/call") {
        const params = (msg.params ?? {}) as { name?: unknown; arguments?: unknown };
        const name = typeof params.name === "string" && params.name ? params.name : "<invalid>";
        const seq = record({
          type: "tool_call",
          tool: { server: o.serverName, name },
          body: { args: params.arguments ?? {} },
        });
        if (seq !== undefined) pending.set(idKey(msg.id), { seq, name, started: now() });
      } else if (msg.method === "initialize") {
        const p = (msg.params ?? {}) as {
          clientInfo?: { name?: string; version?: string };
          protocolVersion?: string;
        };
        record({
          type: "note",
          meta: {
            event: "mcp_initialize",
            mcp_client: `${p.clientInfo?.name ?? "?"}/${p.clientInfo?.version ?? "?"}`.slice(
              0,
              128,
            ),
            ...(p.protocolVersion ? { mcp_protocol: p.protocolVersion.slice(0, 128) } : {}),
          },
          body: {
            args: { clientInfo: p.clientInfo ?? null, protocolVersion: p.protocolVersion ?? null },
          },
        });
      }
    } else if (isJSONRPCNotification(msg) && msg.method === "notifications/cancelled") {
      const id = (msg.params as { requestId?: string | number } | undefined)?.requestId;
      if (id !== undefined) finish(idKey(id), { cancelled: true }, true, { cancelled: "1" });
    }
    send(o.upstream, msg, "up");
  };

  o.upstream.onmessage = (msg) => {
    if (isJSONRPCResultResponse(msg)) {
      const result = msg.result as { isError?: unknown };
      finish(idKey(msg.id), msg.result, result?.isError === true);
    } else if (isJSONRPCErrorResponse(msg) && msg.id !== undefined && msg.id !== null) {
      finish(idKey(msg.id), { error: msg.error }, true);
    }
    send(o.downstream, msg, "down");
  };

  const closeAll = async () => {
    if (closed) return;
    closed = true;
    for (const key of [...pending.keys()])
      finish(key, { error: "upstream_closed" }, true, { reason: "upstream_closed" });
    await Promise.allSettled([o.upstream.close(), o.downstream.close()]);
    o.onClose?.();
  };
  o.upstream.onclose = () => void closeAll();
  o.downstream.onclose = () => void closeAll();
  o.upstream.onerror = (e) => o.log?.warn({ err: e.name }, "upstream transport error");
  o.downstream.onerror = (e) => o.log?.warn({ err: e.name }, "downstream transport error");

  return {
    async start() {
      await o.upstream.start();
      await o.downstream.start();
    },
    close: closeAll,
  };
}
