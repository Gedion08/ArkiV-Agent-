// S7 (createdBy + gte(seq_from) + orderBy at scale) and S8 (write/query rates with an access key).
// Scaled down from 10k to N entities (default 1000) to fit the testnet budget: tiny frames, 12 h
// lifetime, locked like real batches. 18 creates + 18 locks per tx = 36 ops, the most the
// write-safety floor (1M + 400k·(N−1) ≤ half block) allows.
// Run: node --no-warnings --import ./tools/ts/register.mjs tools/spikes/s7-s8.ts [N] [agentKey to skip loading]
import { ExpirationTime } from "@arkiv-network/sdk";
import { asc, eq, gte } from "@arkiv-network/sdk/query";
import { u64 } from "@arkiv-network/sdk/schema";
import { type Hex, keccak256, toHex } from "viem";
import { EVIDENCE_LOCK_ADDRESS } from "../../packages/core/src/constants.ts";
import { httpStatuses, json, publicClient } from "./env.ts";
import { guardedWallet, sanitize } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const N = Number(process.argv[2] ?? 1000);
const PER_TX = 18;
const g = guardedWallet("AFR_ARKIV_WRITER_KEY", 1_000_000_000_000_000_000n); // 1 tGLM reserved cap
const agentKey =
  (process.argv[3] as Hex | undefined) ?? keccak256(toHex(`afr-spike-s7-${Date.now()}`));
const out: Record<string, unknown> = { agentKey, N };
const pct = (xs: number[], p: number) =>
  [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(xs.length * p))];

if (!process.argv[3]) {
  const t0 = Date.now();
  let gasUsed = 0n;
  let cost = 0n;
  const txMs: number[] = [];
  for (let seq = 0; seq < N; seq += PER_TX) {
    const n = Math.min(PER_TX, N - seq);
    const preds = await publicClient.predictEntityKeys({ owner: g.address, count: n });
    const t = Date.now();
    const r = await g.run(`S7 load ${seq}`, () =>
      g.wallet.executeBatch(
        {
          creates: preds.map((p, i) => ({
            schema: Batch,
            values: batchValues(agentKey, BigInt((seq + i) * 100), 64, g.address),
            expiration: ExpirationTime.fromHours(12),
            flags: { readonly: true, permissionlessExtension: true },
            salt: p.salt,
          })),
          ownershipChanges: preds.map((p) => ({
            entityKey: p.key,
            newOwner: EVIDENCE_LOCK_ADDRESS as Hex,
          })),
        },
        g.tx,
      ),
    );
    txMs.push(Date.now() - t);
    gasUsed += r.gasUsed;
    cost += r.cost;
  }
  const mins = (Date.now() - t0) / 60_000;
  out.load = {
    txs: txMs.length,
    minutes: mins.toFixed(1),
    txPerMin: (txMs.length / mins).toFixed(1),
    entitiesPerMin: (N / mins).toFixed(0),
    txMsP50: pct(txMs, 0.5),
    gasPerEntity: (gasUsed / BigInt(N)).toString(),
    costTglm: (Number(cost) / 1e18).toFixed(4),
  };
}

const q = (from: number) =>
  publicClient
    .select({ $key: true, seq_from: true })
    .from(Batch)
    .createdBy(g.address)
    .where(eq("agent_key", agentKey), gte("seq_from", u64(BigInt(from))))
    .orderBy(asc("seq_from"))
    .limit(100);

// Correctness: page through everything with offset; seq_from strictly increasing, all present.
const seen: bigint[] = [];
for (let off = 0; ; off += 100) {
  const page = await q(0).offset(off).fetch();
  for (const e of page.entities) seen.push(BigInt(e.seq_from.value));
  if (page.entities.length < 100) break;
}
out.S7_correctness = {
  rows: seen.length,
  sorted: seen.every((v, i) => i === 0 || v > (seen[i - 1] as bigint)),
  allPresent: seen.length === N,
};

// Latency: 100 sequential queries at random gte offsets.
const lat: number[] = [];
for (let i = 0; i < 100; i++) {
  const t = performance.now();
  await q(Math.floor(Math.random() * N) * 100).fetch();
  lat.push(performance.now() - t);
}
out.S7_latencyMs = {
  p50: pct(lat, 0.5)?.toFixed(0),
  p95: pct(lat, 0.95)?.toFixed(0),
  max: Math.max(...lat).toFixed(0),
};

// S8 query side: 600 queries at concurrency 20; stop counting at the first error class.
let ok = 0;
const errors: Record<string, number> = {};
const t1 = performance.now();
let next = 0;
await Promise.all(
  Array.from({ length: 20 }, async () => {
    while (next < 600) {
      next++;
      await q(0)
        .fetch()
        .then(() => ok++)
        .catch((e) => {
          const k = sanitize(e).slice(0, 120);
          errors[k] = (errors[k] ?? 0) + 1;
        });
    }
  }),
);
const secs = (performance.now() - t1) / 1000;
out.S8_queries = { ok, errors, seconds: secs.toFixed(1), perMin: ((ok / secs) * 60).toFixed(0) };
out.httpStatuses = httpStatuses;
console.log(json(out));
