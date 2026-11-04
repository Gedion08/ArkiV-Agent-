// L8 §4.1: SIWE for smart-contract wallets (ERC-1271) through `siweClient`. A mock wallet (fixtures/
// MockWallet.sol) is placed on anvil, or left undeployed behind its factory (ERC-6492); its owner EOA signs. Needs AFR_PG_URL and AFR_ANVIL_URL (pnpm local:up).
import { randomBytes } from "node:crypto";
import pg from "pg";
import {
  concat,
  createTestClient,
  encodeAbiParameters,
  encodeFunctionData,
  getContractAddress,
  type Hex,
  http,
  pad,
  parseAbi,
  publicActions,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { createSiweMessage } from "viem/siwe";
import { serializeErc6492Signature } from "viem/utils";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { buildServer, localKeyWrapper, migrate } from "../src/index.js";
import {
  MOCK_WALLET_FACTORY_RUNTIME,
  MOCK_WALLET_INIT,
  MOCK_WALLET_RUNTIME,
} from "./fixtures/mock-wallet.js";

const PG = process.env.AFR_PG_URL;
const ANVIL = process.env.AFR_ANVIL_URL;
const DOMAIN = "app.afr.test";

describe.skipIf(!PG || !ANVIL)("SIWE with ERC-1271 wallets", () => {
  const schema = `afr_api_1271_${randomBytes(4).toString("hex")}`;
  const chain = createTestClient({ chain: foundry, mode: "anvil", transport: http(ANVIL) }).extend(
    publicActions,
  );
  let pool: pg.Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    const admin = new pg.Pool({ connectionString: PG, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    pool = new pg.Pool({ connectionString: PG, max: 2, options: `-c search_path=${schema}` });
    await migrate(pool);
    app = await buildServer({
      pool,
      siweDomain: DOMAIN,
      keys: localKeyWrapper(randomBytes(32)),
      siweClient: chain,
    });
  });
  afterAll(async () => {
    await app?.close();
    await pool?.query(`DROP SCHEMA ${schema} CASCADE`);
    await pool?.end();
  });

  /** A fresh wallet contract owned by `owner`, at a random address. */
  async function wallet(owner: Hex): Promise<Hex> {
    const address = `0x${randomBytes(20).toString("hex")}` as Hex;
    await chain.setCode({ address, bytecode: MOCK_WALLET_RUNTIME });
    await chain.setStorageAt({ address, index: 0, value: pad(owner) });
    return address;
  }

  async function siwe(
    address: Hex,
    sign: (m: string) => Promise<Hex>,
    chainId: number = foundry.id,
  ) {
    const remoteAddress = `10.${randomBytes(3).join(".")}`;
    const { nonce } = (
      await app.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress })
    ).json();
    const message = createSiweMessage({
      address,
      chainId,
      domain: DOMAIN,
      nonce,
      uri: `https://${DOMAIN}`,
      version: "1",
    });
    return app.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message, signature: await sign(message) },
      remoteAddress,
    });
  }

  test("the owner's signature logs the wallet in; the user is the contract address", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const w = await wallet(owner.address);
    const res = await siwe(w, (message) => owner.signMessage({ message }));
    expect(res.statusCode).toBe(200);
    expect(res.json().user.wallet).toBe(w.toLowerCase());
  });

  test("a non-owner's signature, the wrong chain, or an EOA impersonation is refused", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const intruder = privateKeyToAccount(generatePrivateKey());
    const w = await wallet(owner.address);
    expect((await siwe(w, (message) => intruder.signMessage({ message }))).statusCode).toBe(401);
    // a message naming another chain never reaches the client (it only knows its own chain)
    expect((await siwe(w, (message) => owner.signMessage({ message }), 8453)).statusCode).toBe(401);
    // no code at the address: an EOA signature must recover to it
    const eoa = `0x${randomBytes(20).toString("hex")}` as Hex;
    expect((await siwe(eoa, (message) => owner.signMessage({ message }))).statusCode).toBe(401);
  });

  /** A counterfactual MockWallet for `owner` behind a fresh factory: its address and deploy calldata. */
  async function counterfactual(owner: Hex, factory?: Hex) {
    const f = factory ?? (`0x${randomBytes(20).toString("hex")}` as Hex);
    if (!factory) await chain.setCode({ address: f, bytecode: MOCK_WALLET_FACTORY_RUNTIME as Hex });
    const salt = `0x${randomBytes(32).toString("hex")}` as Hex;
    const address = getContractAddress({
      opcode: "CREATE2",
      from: f,
      salt,
      bytecode: concat([
        MOCK_WALLET_INIT as Hex,
        encodeAbiParameters([{ type: "address" }], [owner]),
      ]),
    });
    const data = encodeFunctionData({
      abi: parseAbi(["function deploy(address owner, bytes32 salt) returns (address)"]),
      functionName: "deploy",
      args: [owner, salt],
    });
    return { factory: f, address, data };
  }
  const wrapped =
    (factory: Hex, data: Hex, by: ReturnType<typeof privateKeyToAccount>) =>
    async (message: string) =>
      serializeErc6492Signature({
        address: factory,
        data,
        signature: await by.signMessage({ message }),
      });

  test("ERC-6492: a not-yet-deployed wallet logs in via its factory calldata; nothing is deployed", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const intruder = privateKeyToAccount(generatePrivateKey());
    const cf = await counterfactual(owner.address);
    expect((await siwe(cf.address, wrapped(cf.factory, cf.data, intruder))).statusCode).toBe(401);
    const res = await siwe(cf.address, wrapped(cf.factory, cf.data, owner));
    expect(res.statusCode).toBe(200);
    expect(res.json().user.wallet).toBe(cf.address.toLowerCase());
    expect(await chain.getCode({ address: cf.address })).toBeUndefined(); // verified by simulation only
  });

  test("ERC-6492 attacks: own wallet via the same factory, reverting or bogus factory, malformed wrapper → 401", async () => {
    const victim = privateKeyToAccount(generatePrivateKey());
    const intruder = privateKeyToAccount(generatePrivateKey());
    const cf = await counterfactual(victim.address);
    // the intruder's calldata deploys *their* wallet, which lands at another address than the victim's
    const theirs = await counterfactual(intruder.address, cf.factory);
    const own = await siwe(cf.address, wrapped(cf.factory, theirs.data, intruder));
    expect(own.statusCode).toBe(401);
    // calldata the factory rejects, and a "factory" with no code
    const bogusFactory = `0x${randomBytes(20).toString("hex")}` as Hex;
    for (const [f, d] of [
      [cf.factory, "0xdeadbeef"],
      [bogusFactory, cf.data],
    ] as const)
      expect((await siwe(cf.address, wrapped(f, d, victim))).statusCode).toBe(401);
    // the 6492 magic suffix around bytes that don't decode
    const magic = "6492649264926492649264926492649264926492649264926492649264926492";
    expect((await siwe(cf.address, async () => `0x1234${magic}` as Hex)).statusCode).toBe(401);
    expect(await chain.getCode({ address: cf.address })).toBeUndefined();
  });

  test("ERC-6492 then deployed: the same wallet keeps its user with plain 1271 and with the wrapper", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const cf = await counterfactual(owner.address);
    const before = await siwe(cf.address, wrapped(cf.factory, cf.data, owner));
    expect(before.statusCode).toBe(200);
    const deployer = `0x${randomBytes(20).toString("hex")}` as Hex;
    await chain.setBalance({ address: deployer, value: 10n ** 18n });
    await chain.impersonateAccount({ address: deployer });
    await chain.sendUnsignedTransaction({ from: deployer, to: cf.factory, data: cf.data });
    await chain.mine({ blocks: 1 });
    expect(await chain.getCode({ address: cf.address })).toBeDefined();
    for (const sign of [
      (message: string) => owner.signMessage({ message }),
      wrapped(cf.factory, cf.data, owner), // deployed: the wrapper's calldata is skipped
    ]) {
      const r = await siwe(cf.address, sign);
      expect(r.statusCode).toBe(200);
      expect(r.json().user.id).toBe(before.json().user.id);
    }
  });

  test("without a siweClient, contract-wallet signatures are refused (401), not an error", async () => {
    const plain = await buildServer({
      pool,
      siweDomain: DOMAIN,
      keys: localKeyWrapper(randomBytes(32)),
    });
    const owner = privateKeyToAccount(generatePrivateKey());
    const cf = await counterfactual(owner.address);
    const { nonce } = (
      await plain.inject({ method: "GET", url: "/v1/auth/nonce", remoteAddress: "10.9.9.9" })
    ).json();
    const message = createSiweMessage({
      address: cf.address,
      chainId: foundry.id,
      domain: DOMAIN,
      nonce,
      uri: `https://${DOMAIN}`,
      version: "1",
    });
    const res = await plain.inject({
      method: "POST",
      url: "/v1/auth/siwe",
      payload: { message, signature: await wrapped(cf.factory, cf.data, owner)(message) },
      remoteAddress: "10.9.9.9",
    });
    expect(res.statusCode).toBe(401);
    await plain.close();
  });
});
