// P3-04 A6/A7 against the real ERC-8004 IdentityRegistry on an anvil fork of Base Sepolia: register an
// agent, transfer it, then hand it to an ERC-1271 wallet. Nothing is sent to Base Sepolia itself.
// Needs `anvil` and BASE_SEPOLIA_RPC_URL (an archive-capable RPC; https://sepolia.base.org works).
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { typedData } from "@afr/core";
import {
  createPublicClient,
  createWalletClient,
  type Hex,
  http,
  type PublicClient,
  pad,
  parseEventLogs,
  type TypedDataDefinition,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  ERC8004_IDENTITY_REGISTRY,
  IDENTITY_REGISTRY_ABI,
  operatorAt,
  REGISTRATION_TYPE,
  resolveAgent,
  verifyOperatorSig,
} from "../src/index.js";
import { MOCK_WALLET_RUNTIME } from "./fixtures/mock-wallet.js";

const ANVIL = [process.env.ANVIL, "anvil", join(homedir(), ".foundry/bin/anvil")].find(
  (b) => b && spawnSync(b, ["--version"]).status === 0,
);
const FORK = process.env.BASE_SEPOLIA_RPC_URL;
const REGISTRY = ERC8004_IDENTITY_REGISTRY[84532] as Hex;
// anvil's default dev keys #1..#3
const A = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const B = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const SAFE_OWNER = privateKeyToAccount(
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
);
const WALLET = "0x00000000000000000000000000000000000a1271" as Hex;

let anvil: ChildProcess;
let url: string;
let pc: PublicClient;
const rpc = (method: string, params: unknown[]) => pc.request({ method, params } as never);
const wallet = (account: typeof A) =>
  createWalletClient({ account, chain: baseSepolia, transport: http(url) });
async function send(account: typeof A, fn: "register" | "transferFrom", args: unknown[]) {
  const hash = await wallet(account).writeContract({
    address: REGISTRY,
    abi: IDENTITY_REGISTRY_ABI,
    functionName: fn,
    args,
  } as never);
  const r = await pc.waitForTransactionReceipt({ hash });
  expect(r.status).toBe("success");
  return { r, ts: (await pc.getBlock({ blockNumber: r.blockNumber })).timestamp };
}
const later = async (s: number) => {
  await rpc("evm_increaseTime", [s]);
  await rpc("evm_mine", []);
};

const reg = {
  type: REGISTRATION_TYPE,
  name: "AFR fork test",
  services: [
    {
      name: "afr",
      endpoint: "https://verify.afr.dev/agents/test",
      version: "afr/1",
      afr: {
        agentKey: `0x${"cd".repeat(32)}`,
        arkiv: { chainId: 7794095, schemas: ["afr.batch.v1"], writers: [A.address] },
      },
    },
  ],
};

beforeAll(async () => {
  if (!ANVIL || !FORK) return;
  const port = 20000 + Math.floor(Math.random() * 20000);
  url = `http://127.0.0.1:${port}`;
  anvil = spawn(ANVIL, ["--port", String(port), "--fork-url", FORK, "--silent"], {
    stdio: "ignore",
  });
  pc = createPublicClient({ chain: baseSepolia, transport: http(url) }) as PublicClient;
  for (let i = 0; i < 300 && !(await pc.getChainId().catch(() => 0)); i++)
    await new Promise((r) => setTimeout(r, 100));
}, 60_000);
afterAll(() => anvil?.kill());

describe.skipIf(!ANVIL || !FORK)("P3-04 identity on a Base Sepolia fork", () => {
  test("A6 resolve a registered agent; operatorAt follows a transfer. A7 ERC-1271 operator sig", async () => {
    // register (A), as the dashboard would, with a data: registration file carrying an afr entry
    const uri = `data:application/json;base64,${btoa(JSON.stringify(reg))}`;
    const minted = await send(A, "register", [uri]);
    const [ev] = parseEventLogs({
      abi: IDENTITY_REGISTRY_ABI,
      eventName: "Registered",
      logs: minted.r.logs,
    });
    const agentId = `eip155:84532:${REGISTRY}:${ev?.args.agentId}`;

    const resolved = await resolveAgent(agentId, pc);
    expect(resolved.owner).toBe(A.address.toLowerCase());
    expect(resolved.uri).toBe(uri);
    expect(resolved.afr?.afr.agentKey).toBe(reg.services[0]?.afr.agentKey);
    expect(resolved.agentWallet).toBe(A.address.toLowerCase()); // register() sets it to the caller

    await later(100);
    const moved = await send(A, "transferFrom", [A.address, B.address, ev?.args.agentId]);
    await later(100);
    expect(await operatorAt(agentId, minted.ts, pc)).toBe(A.address.toLowerCase());
    expect(await operatorAt(agentId, moved.ts - 1n, pc)).toBe(A.address.toLowerCase());
    expect(await operatorAt(agentId, moved.ts, pc)).toBe(B.address.toLowerCase());
    await expect(operatorAt(agentId, minted.ts - 1n, pc)).rejects.toMatchObject({
      code: "AGENT_NOT_REGISTERED",
    });
    expect((await resolveAgent(agentId, pc)).agentWallet).toBeUndefined(); // cleared on transfer

    // a Delegation signed by whoever was operator at notBefore
    const td = (notBefore: bigint) =>
      typedData(84532, "Delegation", {
        agentKey: reg.services[0]?.afr.agentKey,
        lane: 0,
        sessionKey: A.address,
        notBefore,
        notAfter: notBefore + 3600n,
        scope: 1,
        recorder: "test",
        nonce: 1n,
      }) as unknown as TypedDataDefinition;
    const sign = (who: typeof A, d: TypedDataDefinition) => who.signTypedData(d as never);
    const atB = td(moved.ts);
    expect(await verifyOperatorSig(agentId, atB, await sign(B, atB), moved.ts, pc)).toMatchObject({
      ok: true,
      method: "ecdsa",
    });
    expect((await verifyOperatorSig(agentId, atB, await sign(A, atB), moved.ts, pc)).ok).toBe(
      false,
    );
    const preTransfer = td(moved.ts - 1n); // A, the operator then, still verifies for that time
    expect(
      (await verifyOperatorSig(agentId, preTransfer, await sign(A, preTransfer), moved.ts - 1n, pc))
        .ok,
    ).toBe(true);

    // A7: the agent moves to a contract wallet (ERC-1271; a Safe in production)
    await rpc("anvil_setCode", [WALLET, MOCK_WALLET_RUNTIME]);
    await rpc("anvil_setStorageAt", [
      WALLET,
      pad("0x0", { size: 32 }),
      pad(SAFE_OWNER.address, { size: 32 }),
    ]);
    await later(100);
    const toSafe = await send(B, "transferFrom", [B.address, WALLET, ev?.args.agentId]);
    const atSafe = td(toSafe.ts);
    const good = await verifyOperatorSig(
      agentId,
      atSafe,
      await sign(SAFE_OWNER, atSafe),
      toSafe.ts,
      pc,
    );
    expect(good).toMatchObject({ ok: true, method: "erc1271", operator: WALLET });
    expect(good.note).toMatch(/current block/);
    expect(
      await verifyOperatorSig(agentId, atSafe, await sign(B, atSafe), toSafe.ts, pc),
    ).toMatchObject({ ok: false, method: "erc1271" });
  }, 180_000);
});
