// L8 §4.1: SIWE for smart-contract wallets (ERC-1271) through `siweClient`. A mock wallet (fixtures/
// MockWallet.sol) is placed on anvil; its owner EOA signs. Needs AFR_PG_URL and AFR_ANVIL_URL (pnpm local:up).
import { randomBytes } from "node:crypto";
import pg from "pg";
import { createTestClient, type Hex, http, pad, publicActions } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { createSiweMessage } from "viem/siwe";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { buildServer, localKeyWrapper, migrate } from "../src/index.js";
import { MOCK_WALLET_RUNTIME } from "./fixtures/mock-wallet.js";

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
});
