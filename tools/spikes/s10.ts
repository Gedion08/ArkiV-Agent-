// S10: does watchEntityEvents deliver every registry event over a long run? Ground truth is an
// independent eth_getLogs poller over the registry (≤ 30-block windows, well inside the ~1000-block
// log horizon). Read-only. Run: node … tools/spikes/s10.ts [minutes=60]
import { ENTITY_EVENTS_ABI } from "@arkiv-network/sdk";
import { decodeEventLog } from "viem";
import { json, publicClient } from "./env.ts";
import { REGISTRY, sanitize } from "./guard.ts";

const minutes = Number(process.argv[2] ?? 60);
const id = (tx: string, i: number) => `${tx}:${i}`;
const watched = new Map<string, string>();
const truth = new Map<string, string>();
const watchErrors: Record<string, number> = {};
const pollErrors: Record<string, number> = {};
const lagBlocks: number[] = [];
const start = await publicClient.getBlockNumber();
let head = start;

const unwatch = publicClient.watchEntityEvents({
  onEvent: (e) => {
    watched.set(id(e.transactionHash, e.logIndex), e.type);
    lagBlocks.push(Number(head - e.blockNumber));
  },
  onError: (e) => {
    const k = sanitize(e).slice(0, 120);
    watchErrors[k] = (watchErrors[k] ?? 0) + 1;
  },
});

let from = start;
const poll = setInterval(async () => {
  try {
    head = await publicClient.getBlockNumber();
    const to = head - 2n; // stay a little behind head
    while (from <= to) {
      const end = from + 29n < to ? from + 29n : to;
      const logs = await publicClient.getLogs({ address: REGISTRY, fromBlock: from, toBlock: end });
      for (const l of logs) {
        try {
          const d = decodeEventLog({ abi: ENTITY_EVENTS_ABI, data: l.data, topics: l.topics });
          truth.set(id(l.transactionHash, l.logIndex), d.eventName);
        } catch {
          /* not an entity event */
        }
      }
      from = end + 1n;
    }
  } catch (e) {
    const k = sanitize(e).slice(0, 120);
    pollErrors[k] = (pollErrors[k] ?? 0) + 1;
  }
}, 10_000);

const report = () => {
  const settled = [...truth.keys()];
  const missed = settled.filter((k) => !watched.has(k));
  const extra = [...watched.keys()].filter((k) => !truth.has(k));
  const byType: Record<string, number> = {};
  for (const t of truth.values()) byType[t] = (byType[t] ?? 0) + 1;
  const sorted = [...lagBlocks].sort((a, b) => a - b);
  return {
    blocks: `${start}..${from - 1n}`,
    truthEvents: truth.size,
    byType,
    watched: watched.size,
    missed: missed.length,
    missedSample: missed.slice(0, 3),
    extraNotYetPolled: extra.length,
    lagBlocksP50: sorted[Math.floor(sorted.length / 2)],
    lagBlocksMax: sorted.at(-1),
    watchErrors,
    pollErrors,
  };
};
const tick = setInterval(
  () => console.log(json({ at: new Date().toISOString(), ...report() })),
  10 * 60_000,
);
await new Promise((r) => setTimeout(r, minutes * 60_000));
clearInterval(tick);
clearInterval(poll);
await new Promise((r) => setTimeout(r, 15_000)); // let the watcher drain the last blocks
unwatch();
console.log(json({ final: true, minutes, ...report() }));
process.exit(0);
