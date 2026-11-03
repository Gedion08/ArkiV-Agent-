// Why does a create with ExpirationTime.max() fail? Simulations only (decoded eth_call).
import { ExpirationTime, MAX_LIFETIME } from "@arkiv-network/sdk";
import { type Hex, keccak256, toHex } from "viem";
import { json } from "./env.ts";
import { dryWallet } from "./guard.ts";
import { Batch, batchValues } from "./schemas.ts";

const writer = "0x952dB75Bb45C1D17a1ba30B3eAAC83614cBb35aF" as Hex;
const v = batchValues(keccak256(toHex("x")), 0n, 1024, writer);
const sim = (e: ReturnType<typeof ExpirationTime.fromDays>) =>
  dryWallet(writer)((w) => w.createEntity(Batch, v, { expiration: e }));
console.log(
  json({
    max: await sim(ExpirationTime.max()),
    maxMinus1Block: await sim(ExpirationTime.fromSeconds(Number(MAX_LIFETIME - 1n) * 2)),
    days180: await sim(ExpirationTime.fromDays(180)),
    days182: await sim(ExpirationTime.fromDays(182)),
  }),
);
