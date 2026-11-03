// S2 (names), S3 (create + lock in one executeBatch via predicted key), S9 (extension rules).
// Writes: 2 txs (≈0.01 tGLM at 1 gwei). Simulations need no key.
// Run: node --no-warnings --import ./tools/ts/register.mjs tools/spikes/s2-s3-s9.ts
import { ExpirationTime } from "@arkiv-network/sdk";
import { eq } from "@arkiv-network/sdk/query";
import { u64 } from "@arkiv-network/sdk/schema";
import { type Hex, keccak256, toHex } from "viem";
import { EVIDENCE_LOCK_ADDRESS } from "../../packages/core/src/constants.ts";
import { json, publicClient } from "./env.ts";
import { dryWallet, guardedWallet } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const g = guardedWallet("AFR_ARKIV_WRITER_KEY", 50_000_000_000_000_000n); // 0.05 tGLM cap
const agentKey = keccak256(toHex(`afr-spike-${Date.now()}`));
const out: Record<string, unknown> = { lock: EVIDENCE_LOCK_ADDRESS, writer: g.address };

// S3: predicted key, create (readonly + permissionlessExtension) + changeOwnership in ONE batch.
const [pred] = await publicClient.predictEntityKeys({ owner: g.address, count: 1 });
if (!pred) throw new Error("no prediction");
const s3 = await g.run("S3 create+lock", () =>
  g.wallet.executeBatch(
    {
      creates: [
        {
          schema: Batch,
          values: batchValues(agentKey, 0n, 1024, g.address),
          expiration: ExpirationTime.fromDays(1),
          flags: { readonly: true, permissionlessExtension: true },
          salt: pred.salt,
        },
      ],
      ownershipChanges: [{ entityKey: pred.key, newOwner: EVIDENCE_LOCK_ADDRESS as Hex }],
    },
    g.tx,
  ),
);
const key = s3.out.createdEntities[0] as Hex;
const e = await publicClient.getEntity(key, Batch);
out.S3 = {
  tx: s3.out.txHash,
  predictedMatches: key.toLowerCase() === pred.key.toLowerCase(),
  owner: e.$owner,
  creator: e.$creator,
  flags: e.$creationFlags,
  expiresAt: e.$expiresAt,
  gasUsed: s3.gasUsed,
  cost: s3.costGlm,
};
// S2: schema name with dots and attribute names with underscores round-trip and are queryable.
const q = await publicClient
  .select({ $key: true, seq_from: true, agent_key: true })
  .from(Batch)
  .where(eq("agent_key", agentKey))
  .limit(5)
  .fetch()
  .catch((err: Error) => ({ error: err.name }));
out.S2 = { seq_from: e.seq_from, agent_key_ok: e.agent_key === agentKey, query: q };

// S9a: the writer is no longer the owner; extend the locked entity for real (third-party extension).
const s9 = await g
  .run("S9 third-party extend locked", () =>
    g.wallet.extendEntity({ entityKey: key, expiration: ExpirationTime.fromDays(2) }, g.tx),
  )
  .then((r) => ({ ok: true, tx: r.out.txHash, gasUsed: r.gasUsed, cost: r.costGlm }))
  .catch((err: Error) => ({ ok: false, error: err.message }));
const after = await publicClient.getEntity(key);
out.S9 = { extend: s9, expiresBefore: e.$expiresAt, expiresAfter: after.$expiresAt };

// S9b–d: simulations from a random third party and from the writer (no signing).
const stranger = keccak256(toHex("afr-spike-stranger")).slice(0, 42) as Hex;
out.S9_sim = {
  strangerExtend: await dryWallet(stranger)((w) =>
    w.extendEntity({ entityKey: key, expiration: ExpirationTime.fromDays(3) }),
  ),
  writerPatchLocked: await dryWallet(g.address)((w) =>
    w.patchEntity({ entityKey: key, schema: Batch, set: { privacy: u64(2n) } } as never),
  ),
  writerTransferLocked: await dryWallet(g.address)((w) =>
    w.changeOwnership({ entityKey: key, newOwner: g.address }),
  ),
  writerDeleteLocked: await dryWallet(g.address)((w) => w.deleteEntity({ entityKey: key })),
};
console.log(json(out));
