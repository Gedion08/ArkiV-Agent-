// S5 edge: where between 120 KiB and 128 KiB does a create stop being accepted, and why?
// Read-only: estimateGas + decoded eth_call on captured calldata.
import { createWalletClient, ExpirationTime } from "@arkiv-network/sdk";
import { custom, type Hex, keccak256, toHex } from "viem";
import { chain, json, publicClient } from "./env.ts";
import { engineCall, REGISTRY, sanitize } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const writer = "0x952dB75Bb45C1D17a1ba30B3eAAC83614cBb35aF" as Hex;
async function calldata(frame: number) {
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
    .createEntity(Batch, batchValues(keccak256(toHex("x")), 0n, frame, writer), {
      expiration: ExpirationTime.fromHours(2),
    })
    .catch(() => {});
  return data as Hex;
}
const rows = [];
for (const kib of [120, 124, 126, 127, 127.5, 128]) {
  const data = await calldata(kib * 1024);
  rows.push({
    kib,
    calldataBytes: (data.length - 2) / 2,
    estimate: await publicClient
      .estimateGas({ account: writer, to: REGISTRY, data, blockTag: "latest" })
      .then(String)
      .catch(sanitize),
    call: await engineCall(writer, data),
  });
}
console.log(json(rows));
