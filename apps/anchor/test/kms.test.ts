// P3-12 KMS signer (L5 §3.3) against a stand-in KMS that answers like AWS: a real Node SubjectPublicKeyInfo
// and DER signatures, half of them high-s. Signatures must match a local account on the same key byte for
// byte, and an anchorRoot signed this way must land on anvil. LocalStack KMS: tools/e2e/test/kms.test.ts.
import { generateKeyPairSync } from "node:crypto";
import { type Hex, parseAbi, recoverTransactionAddress, verifyTypedData, zeroHash } from "viem";
import { privateKeyToAccount, sign } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { derSignature, type KmsApi, kmsAccount, spkiPoint } from "../src/index.js";
import { ANVIL, anchorChain, deployAnchor, startAnvil } from "./fixtures/world.js";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const derInt = (x: bigint) => {
  let h = x.toString(16);
  if (h.length % 2) h = `0${h}`;
  if (Number.parseInt(h.slice(0, 2), 16) >= 0x80) h = `00${h}`;
  return Buffer.concat([Buffer.from([0x02, h.length / 2]), Buffer.from(h, "hex")]);
};
const der = (r: bigint, s: bigint) => {
  const body = Buffer.concat([derInt(r), derInt(s)]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x30, body.length]), body]));
};

/** A secp256k1 key held "in KMS": SPKI from Node, signatures as KMS returns them (s may be high). */
function fakeKms(curve = "secp256k1") {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: curve });
  const d = privateKey.export({ format: "jwk" }).d as string;
  const priv = `0x${Buffer.from(d, "base64url").toString("hex").padStart(64, "0")}` as Hex;
  let calls = 0;
  const api: KmsApi = {
    publicKey: async () => new Uint8Array(publicKey.export({ type: "spki", format: "der" })),
    async sign(digest) {
      const sig = await sign({
        hash: `0x${Buffer.from(digest).toString("hex")}`,
        privateKey: priv,
      });
      const s = BigInt(sig.s);
      return der(BigInt(sig.r), calls++ % 2 ? N - s : s); // every other one high-s, as KMS may return
    },
  };
  return { api, priv };
}

const TX = {
  chainId: 84532,
  type: "eip1559" as const,
  to: `0x${"c0".repeat(20)}` as Hex,
  data: "0x1234" as Hex,
  nonce: 7,
  gas: 100_000n,
  maxFeePerGas: 2_000_000_000n,
  maxPriorityFeePerGas: 1_000_000n,
};

describe("kmsAccount", () => {
  test("address from the SPKI; tx, typed data and messages match a local account byte for byte", async () => {
    const { api, priv } = fakeKms();
    const local = privateKeyToAccount(priv);
    const kms = await kmsAccount(api);
    expect(kms.address).toBe(local.address);
    for (let i = 0; i < 4; i++) {
      const tx = { ...TX, nonce: i };
      const raw = await kms.signTransaction(tx);
      expect(raw).toBe(await local.signTransaction(tx));
      expect(await recoverTransactionAddress({ serializedTransaction: raw as never })).toBe(
        local.address,
      );
    }
    const td = {
      domain: { name: "afr", version: "1", chainId: 84532 },
      types: { Ping: [{ name: "n", type: "uint256" }] },
      primaryType: "Ping" as const,
      message: { n: 1n },
    };
    const sig = await kms.signTypedData(td);
    expect(sig).toBe(await local.signTypedData(td));
    expect(await verifyTypedData({ address: local.address, ...td, signature: sig })).toBe(true);
    expect(await kms.signMessage({ message: "hi" })).toBe(
      await local.signMessage({ message: "hi" }),
    );
  });

  test("a signature from another key, a P-256 key, and malformed DER are refused", async () => {
    const a = fakeKms();
    const b = fakeKms();
    const crossed = await kmsAccount({ publicKey: a.api.publicKey, sign: b.api.sign });
    await expect(crossed.signTransaction(TX)).rejects.toMatchObject({ code: "KMS_RECOVER" });

    const p256 = fakeKms("prime256v1");
    // P-256 SPKI parses (same shape) but yields a different address than any secp256k1 signature
    await expect(
      (await kmsAccount({ publicKey: p256.api.publicKey, sign: a.api.sign })).signTransaction(TX),
    ).rejects.toMatchObject({ code: "KMS_RECOVER" });

    const good = der(1n, 2n);
    expect(derSignature(good)).toEqual({ r: 1n, s: 2n });
    expect(derSignature(der(1n, N - 2n))).toEqual({ r: 1n, s: 2n });
    for (const bad of [
      new Uint8Array([...good, 0]), // trailing byte
      good.slice(0, -1), // truncated
      der(0n, 2n),
      der(1n, N),
      new Uint8Array([0x31, ...good.slice(1)]), // not a SEQUENCE
    ])
      expect(() => derSignature(bad)).toThrow(expect.objectContaining({ code: "KMS_DER" }));
    const spki = await a.api.publicKey();
    expect(spkiPoint(spki)).toMatch(/^0x04[0-9a-f]{128}$/);
    expect(() => spkiPoint(new Uint8Array([...spki, 0]))).toThrow(
      expect.objectContaining({ code: "KMS_DER" }),
    );
  });
});

describe.skipIf(!ANVIL)("kmsAccount on anvil", () => {
  let anvil: Awaited<ReturnType<typeof startAnvil>>;
  beforeAll(async () => {
    anvil = await startAnvil();
  }, 30_000);
  afterAll(() => anvil?.stop());

  test("an anchorRoot signed through KMS is mined from the KMS address", async () => {
    const kms = await kmsAccount(fakeKms().api);
    const pc = anvil.pc;
    await pc.request({
      method: "anvil_setBalance",
      params: [kms.address, "0xde0b6b3a7640000"],
    } as never);
    const contract = await deployAnchor(anvil.url, pc, [kms.address]);
    const chain = anchorChain(pc, contract, kms);
    const root = `0x${"ab".repeat(32)}` as Hex;
    const { raw, hash } = await chain.sign(root, 1, zeroHash);
    await chain.broadcast(raw);
    const r = await pc.waitForTransactionReceipt({ hash });
    expect([r.status, r.from]).toEqual(["success", kms.address.toLowerCase()]);
    const epoch = await pc.readContract({
      address: contract,
      abi: parseAbi(["function epochOf(bytes32) view returns (uint64)"]),
      functionName: "epochOf",
      args: [root],
    });
    expect(epoch).toBeGreaterThan(0n);
  });
});
