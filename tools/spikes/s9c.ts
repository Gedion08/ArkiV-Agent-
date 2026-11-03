// S9 diagnosis: eth_call (not estimateGas, which drops revert data on Rabdi) of an ExtendExpiry op
// from the writer and a stranger, decoding the engine error. Read-only.
import {
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  keccak256,
  parseAbi,
  parseAbiParameters,
  toHex,
} from "viem";
import { json, publicClient } from "./env.ts";
import { engineCall as call } from "./guard.ts";

const EXEC = parseAbi(["function execute((uint8 operation, bytes operationData)[] ops)"]);
const extend = (key: Hex, minLifetime: bigint) =>
  encodeFunctionData({
    abi: EXEC,
    args: [
      [
        {
          operation: 3,
          operationData: encodeAbiParameters(
            parseAbiParameters("(bytes32 entityKey, uint64 expiresAt, uint64 minLifetime)"),
            [{ entityKey: key, expiresAt: 0n, minLifetime }],
          ),
        },
      ],
    ],
  });
const [locked, control] = process.argv.slice(2) as [Hex, Hex];
const writer = "0x952dB75Bb45C1D17a1ba30B3eAAC83614cBb35aF";
const stranger = keccak256(toHex("afr-spike-stranger")).slice(0, 42) as Hex;
const days = (d: number) => BigInt(d * 43200);
const e = await publicClient.getEntity(locked);
console.log(
  json({
    head: await publicClient.getBlockNumber(),
    lockedExpiresAt: e.$expiresAt,
    empty: await call(writer, encodeFunctionData({ abi: EXEC, args: [[]] })),
    writerLocked4d: await call(writer, extend(locked, days(4))),
    strangerLocked4d: await call(stranger, extend(locked, days(4))),
    strangerLocked1d: await call(stranger, extend(locked, days(1))),
    writerControl4d: await call(writer, extend(control, days(4))),
  }),
);
