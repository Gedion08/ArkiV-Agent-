// RecorderAnchor deployments (L5 §2, L7 trusted inputs). A new contract version is a new entry, never an edit.
import type { Hex } from "viem";
import { CHAINS } from "./constants.js";

export interface AnchorContract {
  address: Hex;
  /** Deployment block: event scans start here. */
  fromBlock: bigint;
  version: number;
}

export const ANCHOR_CONTRACTS: Readonly<Record<number, readonly AnchorContract[]>> = {
  [CHAINS.BASE_SEPOLIA]: [
    // tx 0xea312325811cae1fb3c9a58c38476829b680b191eeec5ab7528c9121b333073e, verified on BaseScan
    { address: "0x976cf1d60b3dc477c70b9e649005f5a12202d341", fromBlock: 54399317n, version: 1 },
  ],
};
