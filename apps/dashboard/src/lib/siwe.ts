import type { Hex } from "viem";
import { createSiweMessage } from "viem/siwe";

/** EIP-4361 message for POST /v1/auth/siwe. The API checks the domain (AFR_SIWE_DOMAIN), nonce and expiry. */
export const siweMessage = (o: {
  address: Hex;
  chainId: number;
  nonce: string;
  host: string;
  origin: string;
  now: Date;
}) =>
  createSiweMessage({
    address: o.address,
    chainId: o.chainId,
    nonce: o.nonce,
    domain: o.host,
    uri: o.origin,
    version: "1",
    statement: "Sign in to Agent Flight Recorder. This is not a transaction and costs no gas.",
    issuedAt: o.now,
    expirationTime: new Date(o.now.getTime() + 10 * 60_000),
  });
