// A throwaway anvil per test file, plus anvil's well-known dev accounts. Needs `anvil` (Foundry); tests
// skip when ANVIL is undefined.
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  type Hex,
  http,
  type PublicClient,
  parseEther,
  type TestClient,
  type WalletClient,
} from "viem";
import { type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll } from "vitest";

export const ANVIL = [process.env.ANVIL, join(homedir(), ".foundry/bin/anvil")].find(
  (p) => p && existsSync(p),
);
// anvil's dev accounts 0 and 1
export const WATCHED = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
export const OTHER = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
export const SINK = `0x${"ee".repeat(20)}` as Hex;
export const CHAIN = BigInt(foundry.id);

export interface Anvil {
  url: string;
  pc: PublicClient;
  testClient(): TestClient;
  wallet(from?: PrivateKeyAccount): WalletClient;
  /** A plain value transfer, waited for. */
  send(from?: PrivateKeyAccount): Promise<Hex>;
}

/** Starts anvil for this file (beforeAll) and stops it (afterAll). */
export function useAnvil(): Anvil {
  let proc: ChildProcess | undefined;
  const a = { url: "", pc: undefined as unknown as PublicClient };
  beforeAll(async () => {
    if (!ANVIL) return;
    const port = 20000 + Math.floor(Math.random() * 20000);
    a.url = `http://127.0.0.1:${port}`;
    proc = spawn(ANVIL, ["--port", String(port), "--silent"], { stdio: "ignore" });
    a.pc = createPublicClient({ chain: foundry, transport: http(a.url) }) as PublicClient;
    for (let i = 0; i < 100 && !(await a.pc.getChainId().catch(() => 0)); i++)
      await new Promise((r) => setTimeout(r, 100));
  });
  afterAll(() => proc?.kill());
  const testClient = (): TestClient =>
    createTestClient({ chain: foundry, mode: "anvil", transport: http(a.url) });
  const wallet = (from = WATCHED): WalletClient =>
    createWalletClient({ account: from, chain: foundry, transport: http(a.url) });
  const send = async (from = WATCHED) => {
    const hash = await wallet(from).sendTransaction({
      account: from,
      chain: foundry,
      to: SINK,
      value: parseEther("0.001"),
    });
    await a.pc.waitForTransactionReceipt({ hash });
    return hash;
  };
  return Object.assign(a, { testClient, wallet, send });
}
