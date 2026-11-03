// P1-17 wrapTool / wrapAnthropic / note, and fail-open capture.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyRecords } from "@afr/core";
import { createCanary, createLogger, memoryDestination } from "@afr/log";
import { afterEach, expect, test } from "vitest";
import { type Afr, createRecorder } from "../src/index.js";

const opened: Afr[] = [];
afterEach(async () => {
  for (const a of opened.splice(0)) await a.close().catch(() => {});
});

async function afr(extra: Record<string, unknown> = {}, logDest = memoryDestination()) {
  const a = await createRecorder({
    config: {
      version: 1,
      agent: { id: "eip155:84532:0x00000000000000000000000000000000000a8004:7" },
      data_dir: mkdtempSync(join(tmpdir(), "afr-sdkw-")),
      delegation: { mode: "operator_env" },
      ...extra,
    },
    env: { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02` },
    logger: createLogger({ name: "t", destination: logDest }),
  });
  opened.push(a);
  return a;
}

const recs = (a: Afr) => [...a.recorder.journal.iterate()];

test("wrapTool records call + result, and errors are recorded then rethrown", async () => {
  const a = await afr();
  const price = a.wrapTool("price.get", async (sym: string, n: bigint) => ({ sym, px: n * 2n }));
  expect(await price("ETH", 21n)).toEqual({ sym: "ETH", px: 42n });
  const boom = a.wrapTool("boom", () => {
    throw new TypeError("nope");
  });
  await expect(boom()).rejects.toThrow("nope");

  const r = recs(a);
  const [c1, r1, c2, r2] = r.slice(1);
  expect([c1?.type, r1?.type, c2?.type, r2?.type]).toEqual([
    "tool_call",
    "tool_result",
    "tool_call",
    "tool_result",
  ]);
  expect(a.recorder.journal.readBody(c1!.seq).args).toEqual(["ETH", "21"]);
  expect(a.recorder.journal.readBody(r1!.seq).result).toEqual({ sym: "ETH", px: "42" });
  expect(r1!.header).toMatchObject({
    ref_seq: c1!.header.seq,
    tool: { name: "price.get", is_error: false },
  });
  expect(r2!.header.tool?.is_error).toBe(true);
  expect(a.recorder.journal.readBody(r2!.seq).result).toEqual({ error: "TypeError" });
  expect(
    await verifyRecords(r.map((x) => ({ header: x.header, sig: x.sig, hash: x.hash }))),
  ).toEqual([]);
});

function fakeAnthropic(fail = false) {
  const msg = {
    model: "claude-opus-5-5-20261001",
    content: [{ type: "text", text: "hi there" }],
    usage: { input_tokens: 12, output_tokens: 3 },
  };
  // mimics the SDK's APIPromise: a promise with extra methods that must survive wrapping
  const apiPromise = () => {
    const p = fail ? Promise.reject(new RangeError("overloaded")) : Promise.resolve(msg);
    return Object.assign(p, { withResponse: () => p.then((data) => ({ data })) });
  };
  return {
    other: 1,
    messages: {
      create: (_params: Record<string, unknown>) => apiPromise(),
      stream: (_params: Record<string, unknown>) => ({ finalMessage: () => apiPromise(), on() {} }),
    },
  };
}

test("wrapAnthropic records one model_call per response; the SDK promise is returned as-is", async () => {
  const a = await afr();
  const client = a.wrapAnthropic(fakeAnthropic());
  const params = {
    model: "claude-opus-5-5",
    max_tokens: 64,
    system: "be brief",
    messages: [{ role: "user", content: "hello" }],
  };
  const p = client.messages.create(params);
  expect(typeof (p as unknown as { withResponse: unknown }).withResponse).toBe("function");
  await p;
  await client.messages.stream(params).finalMessage();
  expect(client.other).toBe(1);

  const calls = recs(a).filter((r) => r.type === "model_call");
  expect(calls).toHaveLength(2);
  expect(calls[0]!.header.model).toEqual({
    provider: "anthropic",
    id: "claude-opus-5-5",
    version: "claude-opus-5-5-20261001",
    tokens_in: "12",
    tokens_out: "3",
  });
  const body = a.recorder.journal.readBody(calls[0]!.seq);
  expect(body.context).toEqual({
    system: "be brief",
    messages: [{ role: "user", content: "hello" }],
    params: { model: "claude-opus-5-5", max_tokens: 64 },
  });
  expect(body.output).toEqual([{ type: "text", text: "hi there" }]);
});

test("wrapAnthropic records errors with meta.error and leaves the rejection to the caller", async () => {
  const a = await afr();
  const client = a.wrapAnthropic(fakeAnthropic(true));
  await expect(client.messages.create({ model: "m", messages: [] })).rejects.toThrow("overloaded");
  await new Promise((r) => setTimeout(r, 0));
  const call = recs(a).find((r) => r.type === "model_call");
  expect(call?.header.meta?.error).toBe("RangeError");
});

test("wrapAnthropic refuses context modes it can't honour", async () => {
  const a = await afr({ capture: { context: "hash_only" } });
  expect(() => a.wrapAnthropic(fakeAnthropic())).toThrow(
    expect.objectContaining({ code: "CAPTURE_MODE_UNSUPPORTED" }),
  );
});

test("fail-open: a capture error is logged by code and never reaches the agent; logs carry no body", async () => {
  const canary = createCanary();
  const dest = memoryDestination();
  const a = await afr({}, dest);
  await a.close();
  // recorder closed → capture throws RECORDER_CLOSED; the tool still runs
  const echo = a.wrapTool("echo", async (s: string) => s);
  expect(await echo(canary.value)).toBe(canary.value);
  expect(dest.output()).toMatch(/RECORDER_CLOSED/);
  canary.assertAbsent(dest.output());
});
