// S5 (largest frame accepted with real attrs) + S6 (gas/tGLM per 96 KiB batch vs lifetime) + readonly
// patch rejection for the owner. Writes ≤ ~8 txs under a 0.2 tGLM cap; stops at the first rejection.
// Run: node --no-warnings --import ./tools/ts/register.mjs tools/spikes/s5-s6.ts
import { ExpirationTime } from "@arkiv-network/sdk";
import { u64 } from "@arkiv-network/sdk/schema";
import { type Hex, keccak256, toHex } from "viem";
import { json, publicClient } from "./env.ts";
import { dryWallet, guardedWallet } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const g = guardedWallet("AFR_ARKIV_WRITER_KEY", 200_000_000_000_000_000n);
const agentKey = keccak256(toHex(`afr-spike-s5-${Date.now()}`));
const KiB = 1024;
const out: Record<string, unknown> = {};
let seq = 0n;

async function create(
  label: string,
  frame: number,
  expiration: ReturnType<typeof ExpirationTime.fromDays>,
) {
  seq += 100n;
  const r = await g.run(label, () =>
    g.wallet.executeBatch(
      {
        creates: [
          {
            schema: Batch,
            values: batchValues(agentKey, seq, frame, g.address),
            expiration,
            flags: { readonly: true, permissionlessExtension: true },
          },
        ],
      },
      g.tx,
    ),
  );
  return {
    key: r.out.createdEntities[0] as Hex,
    frame,
    gasUsed: r.gasUsed,
    cost: r.costGlm,
    gasLimit: r.gas,
    estimate: r.estimate,
    calldataBytes: r.calldataBytes,
  };
}

// S6: the 96 KiB × 1 d create is measured by the first run (journal); here measure extensions of a
// 96 KiB entity, whose gas the per-tx bounds also cap. (Creating at max lifetime needs ~15.4M gas,
// over the guard's half-block bound — see s6-curve.ts.)
const d1 = await create("S6 96KiB 1d", 96 * KiB, ExpirationTime.fromDays(1));
const extensions = [];
for (const days of [30, 60]) {
  const r = await g.run(`S6 extend 96KiB to ${days}d`, () =>
    g.wallet.extendEntity({ entityKey: d1.key, expiration: ExpirationTime.fromDays(days) }, g.tx),
  );
  extensions.push({ toDays: days, gasUsed: r.gasUsed, cost: r.costGlm, estimate: r.estimate });
}
out.S6 = { d1, extensions };

// Owner patch of an unlocked readonly entity (simulation only).
out.ownerPatchReadonly = await dryWallet(g.address)((w) =>
  w.patchEntity(Batch, d1.key, { set: { privacy: u64(2n) } }),
);

// S5: walk up to the SDK cap (128 KiB of bytes values); on the first failure, stop and report.
const s5: unknown[] = [];
for (const size of [112 * KiB, 120 * KiB, 128 * KiB]) {
  try {
    s5.push(await create(`S5 ${size / KiB}KiB`, size, ExpirationTime.fromHours(2)));
  } catch (e) {
    s5.push({ frame: size, error: (e as Error).message });
    break;
  }
}
out.S5 = s5;
out.overCap = await create("S5 128KiB+1", 128 * KiB + 1, ExpirationTime.fromHours(2)).catch(
  (e: Error) => e.message,
);
out.balanceAfter = await publicClient.getBalance({ address: g.address, blockTag: "latest" });
console.log(json(out));
