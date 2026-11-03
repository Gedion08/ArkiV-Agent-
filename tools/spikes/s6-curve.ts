// S6: estimated gas of one Batch create vs frame size and lifetime (read-only estimates).
import { createWalletClient, ExpirationTime } from "@arkiv-network/sdk";
import { custom, type Hex, keccak256, toHex } from "viem";
import { chain, json, publicClient } from "./env.ts";
import { REGISTRY, sanitize } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const writer = "0x952dB75Bb45C1D17a1ba30B3eAAC83614cBb35aF" as Hex;
async function calldata(frame: number, e: ReturnType<typeof ExpirationTime.fromDays>) {
  let data: Hex | undefined;
  const w = createWalletClient({
    chain,
    account: writer,
    transport: custom({
      request: async ({ method, params }) => {
        if (method === "eth_estimateGas") {
          data = (params as [{ data: Hex }])[0].data;
          throw new Error("captured");
        }
        return publicClient.request({ method, params } as never);
      },
    }),
  });
  await w
    .createEntity(Batch, batchValues(keccak256(toHex("x")), 0n, frame, writer), { expiration: e })
    .catch(() => {});
  return data as Hex;
}
const KiB = 1024;
const rows = [];
for (const frame of [1 * KiB, 32 * KiB, 96 * KiB]) {
  for (const [name, e] of [
    ["1h", ExpirationTime.fromHours(1)],
    ["1d", ExpirationTime.fromDays(1)],
    ["7d", ExpirationTime.fromDays(7)],
    ["30d", ExpirationTime.fromDays(30)],
    ["90d", ExpirationTime.fromDays(90)],
    ["max", ExpirationTime.max()],
  ] as const) {
    const data = await calldata(frame, e);
    const gas = await publicClient
      .estimateGas({ account: writer, to: REGISTRY, data, blockTag: "latest" })
      .catch((err) => sanitize(err));
    rows.push({ frameKiB: frame / KiB, lifetime: name, gas });
  }
}
console.log(json(rows));
