// R6 (L2 §15): wallet hook on Anvil. sendTransaction, writeContract, deployContract, signTypedData all
// produce records, and tx_sign.tx_hash equals the mined hash. Needs `anvil` (Foundry); CI installs it.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { verifyRecords } from "@afr/core";
import {
  createPublicClient,
  createWalletClient,
  type Hex,
  http,
  parseEther,
  toFunctionSelector,
  verifyMessage,
  verifyTypedData,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { type Afr, createRecorder } from "../src/index.js";

const ANVIL = [process.env.ANVIL, "anvil", join(homedir(), ".foundry/bin/anvil")].find(
  (b) => b && spawnSync(b, ["--version"]).status === 0,
);
// Anvil's default dev accounts #0 (local signing) and #1 (unlocked, JSON-RPC signing)
const PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ADDR1 = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
// init code returning a 1-byte runtime (STOP): every call succeeds
const BYTECODE = "0x600180600b6000396000f300";
const ABI = [
  {
    type: "function",
    name: "ping",
    inputs: [{ name: "x", type: "uint256" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

let anvil: ChildProcess;
let url: string;
let afr: Afr;

beforeAll(async () => {
  if (!ANVIL) return;
  const port = 20000 + Math.floor(Math.random() * 20000);
  url = `http://127.0.0.1:${port}`;
  anvil = spawn(ANVIL, ["--port", String(port), "--silent"], { stdio: "ignore" });
  for (let i = 0; i < 100; i++) {
    const ok = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
    }).then(
      (r) => r.ok,
      () => false,
    );
    if (ok) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  afr = await createRecorder({
    config: {
      version: 1,
      agent: { id: "eip155:84532:0x00000000000000000000000000000000000a8004:7" },
      data_dir: mkdtempSync(join(tmpdir(), "afr-sdk-")),
      delegation: { mode: "operator_env" },
    },
    env: { AFR_OPERATOR_KEY: `0x${"00".repeat(31)}02`, AFR_LOG_LEVEL: "warn" },
  });
}, 30_000);

afterAll(async () => {
  await afr?.close().catch(() => {});
  anvil?.kill();
});

const records = () => [...afr.recorder.journal.iterate()];
const last = (type: string) =>
  records()
    .filter((r) => r.type === type)
    .at(-1);

describe.skipIf(!ANVIL && !process.env.CI)("R6 wallet hook on Anvil", () => {
  test("local account: send, deploy, write, sign — tx_hash matches the mined hash", async () => {
    const account = privateKeyToAccount(PK0);
    const pub = createPublicClient({ chain: foundry, transport: http(url) });
    const wallet = afr.wrapWalletClient(
      createWalletClient({ account, chain: foundry, transport: http(url) }),
    );

    const sent = await wallet.sendTransaction({ to: ADDR1, value: parseEther("0.01") });
    expect((await pub.waitForTransactionReceipt({ hash: sent })).status).toBe("success");
    const sign1 = last("tx_sign")!;
    expect(sign1.header.tx).toMatchObject({
      tx_hash: sent,
      from: account.address.toLowerCase(),
      to: ADDR1,
      value: parseEther("0.01").toString(),
      chain_id: String(foundry.id),
    });
    expect(last("tx_broadcast")!.header).toMatchObject({
      ref_seq: sign1.header.seq,
      tx: { tx_hash: sent, status: "sent" },
    });

    const deployed = await wallet.deployContract({ abi: ABI, bytecode: BYTECODE });
    const rc = await pub.waitForTransactionReceipt({ hash: deployed });
    expect(rc.contractAddress).toBeTruthy();
    expect(last("tx_sign")!.header.tx?.tx_hash).toBe(deployed);
    expect(last("tx_sign")!.header.tx?.to).toBeUndefined();
    expect(afr.recorder.journal.readBody(last("tx_sign")!.seq).calldata).toBe(BYTECODE);

    const written = await wallet.writeContract({
      address: rc.contractAddress as Hex,
      abi: ABI,
      functionName: "ping",
      args: [7n],
    });
    expect((await pub.waitForTransactionReceipt({ hash: written })).status).toBe("success");
    expect(last("tx_sign")!.header.tx).toMatchObject({
      tx_hash: written,
      selector: toFunctionSelector("ping(uint256)"),
    });

    const typed = {
      domain: { name: "AFR test", version: "1", chainId: foundry.id },
      types: { Ping: [{ name: "x", type: "uint256" }] },
      primaryType: "Ping",
      message: { x: 7n },
    } as const;
    const sig = await wallet.signTypedData(typed);
    expect(await verifyTypedData({ ...typed, address: account.address, signature: sig })).toBe(
      true,
    );
    expect(last("msg_sign")!.header.meta).toMatchObject({
      kind: "typed",
      primary_type: "Ping",
      signer: account.address.toLowerCase(),
    });
    expect(afr.recorder.journal.readBody(last("msg_sign")!.seq).args).toMatchObject({
      message: { x: "7" },
    });

    const msig = await wallet.signMessage({ message: "hello" });
    expect(
      await verifyMessage({ address: account.address, message: "hello", signature: msig }),
    ).toBe(true);
    expect(last("msg_sign")!.header.meta?.kind).toBe("personal");
  }, 60_000);

  test("JSON-RPC account: tx_sign without hash, tx_broadcast carries the mined hash", async () => {
    const pub = createPublicClient({ chain: foundry, transport: http(url) });
    const wallet = afr.wrapWalletClient(
      createWalletClient({ account: ADDR1, chain: foundry, transport: http(url) }),
    );
    const hash = await wallet.sendTransaction({ to: ADDR1, value: 1n });
    expect((await pub.waitForTransactionReceipt({ hash })).status).toBe("success");
    const sign = last("tx_sign")!;
    expect(sign.header.tx?.tx_hash).toBeUndefined();
    expect(sign.header.tx).toMatchObject({ from: ADDR1, value: "1" });
    expect(last("tx_broadcast")!.header).toMatchObject({
      ref_seq: sign.header.seq,
      tx: { tx_hash: hash, status: "sent" },
    });
  }, 30_000);

  test("the whole journal verifies", async () => {
    expect(
      await verifyRecords(records().map((r) => ({ header: r.header, sig: r.sig, hash: r.hash }))),
    ).toEqual([]);
  });
});
