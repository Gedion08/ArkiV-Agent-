// P3-12 A4 locally: the anchor service's KMS signer (L5 §3.3) against LocalStack KMS, the same API AWS
// serves: an ECC_SECG_P256K1 key signs an anchorRoot that is mined on anvil from the key's address, and a
// key of the wrong spec is refused. Needs AFR_LOCALSTACK_URL (pnpm local:up) and anvil; skipped without.

import { awsKms, kmsAccount } from "@afr/anchor";
import { CreateKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { type Hex, parseAbi, recoverTransactionAddress, zeroHash } from "viem";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  ANVIL,
  anchorChain,
  deployAnchor,
  startAnvil,
} from "../../../apps/anchor/test/fixtures/world.js";

const LS = process.env.AFR_LOCALSTACK_URL ?? "";

describe.skipIf(!LS || !ANVIL)("KMS anchor signer on LocalStack", () => {
  const kms = new KMSClient({
    endpoint: LS,
    region: "us-east-1",
    credentials: { accessKeyId: "test", secretAccessKey: "test" },
  });
  const key = async (KeySpec: "ECC_SECG_P256K1" | "ECC_NIST_P256") =>
    (
      await kms.send(
        new CreateKeyCommand({ KeySpec, KeyUsage: "SIGN_VERIFY", Description: "afr e2e anchor" }),
      )
    ).KeyMetadata?.KeyId as string;
  let anvil: Awaited<ReturnType<typeof startAnvil>>;
  beforeAll(async () => {
    anvil = await startAnvil();
  }, 30_000);
  afterAll(() => anvil?.stop());

  test("A4: an anchorRoot signed by a KMS key is mined from that key's address", async () => {
    const signer = await kmsAccount(awsKms(kms, await key("ECC_SECG_P256K1")));
    const pc = anvil.pc;
    await pc.request({
      method: "anvil_setBalance",
      params: [signer.address, "0xde0b6b3a7640000"],
    } as never);
    const contract = await deployAnchor(anvil.url, pc, [signer.address]);
    const chain = anchorChain(pc, contract, signer);
    for (const b of ["aa", "bb", "cc"]) {
      // several signatures: KMS returns high-s about half the time
      const root = `0x${b.repeat(32)}` as Hex;
      const { raw, hash } = await chain.sign(root, 1, zeroHash);
      expect(await recoverTransactionAddress({ serializedTransaction: raw as never })).toBe(
        signer.address,
      );
      await chain.broadcast(raw);
      expect((await pc.waitForTransactionReceipt({ hash })).status).toBe("success");
      const epoch = await pc.readContract({
        address: contract,
        abi: parseAbi(["function epochOf(bytes32) view returns (uint64)"]),
        functionName: "epochOf",
        args: [root],
      });
      expect(epoch).toBeGreaterThan(0n);
    }
  }, 60_000);

  test("a P-256 key is refused before anything is signed", async () => {
    await expect(kmsAccount(awsKms(kms, await key("ECC_NIST_P256")))).rejects.toMatchObject({
      code: "KMS_KEY_SPEC",
    });
  });
});
