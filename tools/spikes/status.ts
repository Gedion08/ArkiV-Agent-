// Read-only: chain id, head, gas price, block gas limit, writer balance, block timing.

import { formatEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { json, publicClient } from "./env.ts";

const address = privateKeyToAccount(process.env.AFR_ARKIV_WRITER_KEY as `0x${string}`).address;
const [chainId, head, gasPrice, balance, timing] = await Promise.all([
  publicClient.getChainId(),
  publicClient.getBlock({ blockTag: "latest" }),
  publicClient.getGasPrice(),
  publicClient.getBalance({ address, blockTag: "latest" }),
  publicClient.getBlockTiming(),
]);
console.log(
  json({
    chainId,
    head: head.number,
    gasLimit: head.gasLimit,
    gasPrice,
    address,
    balance: formatEther(balance),
    timing,
  }),
);
