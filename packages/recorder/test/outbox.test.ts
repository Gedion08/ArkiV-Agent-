// P2-14: recorder outbox → API (L2 §10): durable, signed, retried with backoff, no plaintext.
import { createHmac, randomBytes } from "node:crypto";
import { agentKey } from "@afr/core";
import { nonceCommit, recorderSecretHash, recorderStringToSign } from "@afr/crypto";
import { createCanary, type Logger } from "@afr/log";
import { MemoryChain, MemoryStore } from "@afr/store";
import type { Hex } from "viem";
import { describe, expect, test } from "vitest";
import { Recorder } from "../src/index.js";
import { AGENT, env, ready, tmpConfig } from "./fixtures/setup.js";

const AK = agentKey(AGENT);
const WRITER = `0x${"a1".repeat(20)}` as Hex;
const SECRET = "ab".repeat(32);
const TOKEN = `afr_rk_0123456789abcdef_${SECRET}`;
const FROM = `0x${"11".repeat(20)}` as Hex;

interface Call {
  path: string;
  body: string;
  headers: Record<string, string>;
}

const capture = () => {
  const logged: string[] = [];
  const log = (o: unknown) => logged.push(JSON.stringify(o));
  return { logged, logger: { warn: log, error: log, info: log, debug: log } as unknown as Logger };
};

/** A fake API: verifies the L8 §2 signature, records calls, answers with `status()`. */
function fakeApi(status: (c: Call) => number | "down" = () => 200) {
  const calls: Call[] = [];
  const fetchFn: typeof fetch = async (url, init) => {
    const u = new URL(String(url));
    const c = {
      path: u.pathname,
      body: String(init?.body ?? ""),
      headers: init?.headers as Record<string, string>,
    };
    const ts = c.headers["x-afr-timestamp"] as string;
    const want = createHmac("sha256", recorderSecretHash(SECRET))
      .update(recorderStringToSign("POST", c.path, ts, c.body))
      .digest("hex");
    expect(c.headers["x-afr-signature"]).toBe(want);
    expect(c.headers.authorization).toBe(`Bearer ${TOKEN}`);
    const s = status(c);
    if (s === "down") throw new TypeError("fetch failed");
    calls.push(c);
    return new Response("{}", { status: s });
  };
  const of = (p: string) => calls.filter((c) => c.path === p).map((c) => JSON.parse(c.body));
  return { calls, fetchFn, of };
}

function harness(api: ReturnType<typeof fakeApi>, logger?: Logger) {
  const config = tmpConfig({ api: { url: "https://api.afr.test" } });
  const chain = new MemoryChain();
  const watchKey = new Uint8Array(randomBytes(32));
  const clock = { now: Date.now() };
  const start = () =>
    ready(
      Recorder.start({
        config,
        env: { ...env, AFR_API_KEY: TOKEN },
        autoRotate: false,
        now: () => clock.now,
        ...(logger ? { logger } : {}),
        upload: {
          store: new MemoryStore(chain, WRITER),
          tickMs: 3_600_000,
          watchKey,
          apiFetch: api.fetchFn,
        },
      }),
    );
  return { start, watchKey, clock };
}

describe("P2-14 outbox → API", () => {
  test("delegation + checkpoint notices are delivered, signed, and match the journal", async () => {
    const api = fakeApi();
    const rec = await harness(api).start();
    await rec.flush();
    const [d] = api.of("/v1/recorder/delegations");
    expect(d).toMatchObject({ lane: 0, session_key: rec.status().sessionKey.toLowerCase() });
    const [cp] = api.of("/v1/recorder/checkpoints");
    const b = rec.journal.batch(0n);
    expect(cp).toEqual({
      agent_key: AK,
      lane: 0,
      seq_from: "0",
      seq_to: String(b?.seqTo),
      batch_root: b?.batchRoot,
      chain_root: b?.chainRoot,
      entity_key: b?.entityKey,
      arkiv_tx: b?.txHash,
    });
    expect(rec.journal.outboxSize()).toBe(0);
    await rec.close();
  });

  test("tx_sign → tx_intent with watch-key commitments; intents batched in one call", async () => {
    const api = fakeApi();
    const h = harness(api);
    const rec = await h.start();
    for (const nonce of [7n, 8n])
      rec.capture({
        type: "tx_sign",
        tx: { chain_id: 8453n, from: FROM, to: FROM, nonce, value: 0n },
      });
    await rec.flush();
    const calls = api.of("/v1/recorder/intents");
    expect(calls).toHaveLength(1);
    expect(calls[0].items).toEqual(
      [7n, 8n].map((nonce, i) => ({
        agent_key: AK,
        lane: 0,
        seq: String(i + 1),
        chain_id: "8453",
        nonce_commit: nonceCommit(h.watchKey, 8453n, FROM, nonce),
      })),
    );
    await rec.close();
  });

  test("API down → kept with backoff, delivered after a restart; 4xx dropped and logged", async () => {
    let down = true;
    const { logged, logger } = capture();
    const api = fakeApi((c) => (down ? "down" : c.path.endsWith("/delegations") ? 400 : 200));
    const h = harness(api, logger);
    const rec = await h.start();
    await rec.flush();
    expect(rec.journal.outboxSize()).toBe(2); // delegation + checkpoint, nothing delivered
    // the failed delegation backs off; the first failure stops the drain, so the checkpoint is untried
    expect(rec.journal.dueNotices(h.clock.now).map((n) => n.kind)).toEqual(["checkpoint"]);
    const later = rec.journal.dueNotices(h.clock.now + 1000);
    expect(later.map((n) => n.attempts)).toEqual([1, 0]);
    await rec.close(); // session_end adds another checkpoint
    down = false;
    h.clock.now += 60_000;
    const again = await h.start();
    await again.flush();
    expect(again.journal.outboxSize()).toBe(0);
    const seqs = api.of("/v1/recorder/checkpoints").map((c) => c.seq_from);
    expect(seqs).toEqual([...seqs].sort((a, b) => Number(a) - Number(b)));
    expect(seqs.length).toBe(again.journal.batchCounts().verified);
    expect(logged.join()).toContain("OUTBOX_REJECTED"); // the 400 delegations were dropped
    await again.close();
  });

  test("no API key: outbox disabled (logged), nothing queued", async () => {
    const api = fakeApi();
    const { logged, logger } = capture();
    const rec = await ready(
      Recorder.start({
        config: tmpConfig({ api: { url: "https://api.afr.test" } }),
        env,
        autoRotate: false,
        logger,
        upload: {
          store: new MemoryStore(new MemoryChain(), WRITER),
          tickMs: 3_600_000,
          apiFetch: api.fetchFn,
        },
      }),
    );
    await rec.flush();
    expect(api.calls).toEqual([]);
    expect(rec.journal.outboxSize()).toBe(0);
    expect(logged.join()).toContain("API_KEY_MISSING");
    await rec.close();
  });

  test("heartbeat at most every 30 s from the tick", async () => {
    const api = fakeApi();
    const rec = await ready(
      Recorder.start({
        config: tmpConfig({ api: { url: "https://api.afr.test" } }),
        env: { ...env, AFR_API_KEY: TOKEN },
        autoRotate: false,
        upload: {
          store: new MemoryStore(new MemoryChain(), WRITER),
          tickMs: 10,
          apiFetch: api.fetchFn,
        },
      }),
    );
    await new Promise((r) => setTimeout(r, 150));
    const hb = api.of("/v1/recorder/heartbeat");
    expect(hb).toHaveLength(1); // many ticks, one heartbeat
    expect(hb[0]).toMatchObject({ agent_key: AK, lane: 0, store_lag_s: expect.any(Number) });
    expect(hb[0].key_not_after).toMatch(/^\d+$/);
    await rec.close();
  });

  test("canary: plaintext never reaches API request bodies (CLAUDE.md rule 2)", async () => {
    const canary = createCanary();
    const api = fakeApi();
    const rec = await harness(api).start();
    rec.capture({
      type: "tx_sign",
      tx: { chain_id: 1n, from: FROM, to: FROM, nonce: 1n, value: 0n },
      body: { calldata: "0x" },
    });
    rec.capture({
      type: "tool_call",
      tool: { server: "s", name: "t" },
      body: { args: canary.value },
    });
    await rec.flush();
    expect(api.calls.length).toBeGreaterThan(2);
    canary.assertAbsent(...api.calls.map((c) => c.body));
    await rec.close();
  });
});
