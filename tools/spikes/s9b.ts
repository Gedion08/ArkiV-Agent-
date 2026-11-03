// S9 follow-up: readonly patch rejection, stranger vs writer extension, and the control case
// (locked, readonly, NO permissionlessExtension). One write (≈0.0003 tGLM).
// Run: node --no-warnings --import ./tools/ts/register.mjs tools/spikes/s9b.ts <lockedKey>
import { ExpirationTime } from "@arkiv-network/sdk";
import { u64 } from "@arkiv-network/sdk/schema";
import { encodeFunctionData, type Hex, keccak256, parseAbi, toHex } from "viem";
import { EVIDENCE_LOCK_ADDRESS } from "../../packages/core/src/constants.ts";
import { json, publicClient } from "./env.ts";
import { dryWallet, guardedWallet, REGISTRY, sanitize } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const key = process.argv[2] as Hex;
const g = guardedWallet("AFR_ARKIV_WRITER_KEY", 10_000_000_000_000_000n);
const stranger = keccak256(toHex("afr-spike-stranger")).slice(0, 42) as Hex;
const ext = (k: Hex, d: number) => (w: typeof g.wallet) =>
  w.extendEntity({ entityKey: k, expiration: ExpirationTime.fromDays(d) });
const out: Record<string, unknown> = {};
out.writerExtendLocked = await dryWallet(g.address)(ext(key, 4));
out.strangerExtendLocked = await dryWallet(stranger)(ext(key, 4));
out.writerPatchLockedReadonly = await dryWallet(g.address)((w) =>
  w.patchEntity(Batch, key, { set: { privacy: u64(2n) } }),
);
// Is the stranger failure about its zero balance? Empty batch must revert with EmptyBatch data.
const data = encodeFunctionData({
  abi: parseAbi(["function execute((uint8 operation, bytes operationData)[] ops)"]),
  args: [[]],
});
out.strangerEmptyBatch = await publicClient
  .estimateGas({ account: stranger, to: REGISTRY, data })
  .then(() => "ok")
  .catch(sanitize);
out.writerEmptyBatch = await publicClient
  .estimateGas({ account: g.address, to: REGISTRY, data })
  .then(() => "ok")
  .catch(sanitize);

if (process.argv[3]) {
  out.writerExtendControl = await dryWallet(g.address)(ext(process.argv[3] as Hex, 2));
  console.log(json(out));
  process.exit(0);
}
// Control: locked + readonly without permissionlessExtension.
const [pred] = await publicClient.predictEntityKeys({ owner: g.address, count: 1 });
if (!pred) throw new Error("no prediction");
const c = await g.run("S9 control create+lock (no permissionlessExtension)", () =>
  g.wallet.executeBatch(
    {
      creates: [
        {
          schema: Batch,
          values: batchValues(keccak256(toHex("afr-spike-control")), 0n, 256, g.address),
          expiration: ExpirationTime.fromDays(1),
          flags: { readonly: true },
          salt: pred.salt,
        },
      ],
      ownershipChanges: [{ entityKey: pred.key, newOwner: EVIDENCE_LOCK_ADDRESS as Hex }],
    },
    g.tx,
  ),
);
out.control = { key: pred.key, tx: c.out.txHash, cost: c.costGlm };
out.writerExtendControl = await dryWallet(g.address)(ext(pred.key, 2));
console.log(json(out));
