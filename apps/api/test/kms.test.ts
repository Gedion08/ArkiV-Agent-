// L8 §8 envelope keys on AWS KMS (LocalStack). Needs AFR_KMS_ENDPOINT (pnpm local:up). The credentials
// are LocalStack's documented dummies, not real ones.
import { randomBytes } from "node:crypto";
import { CreateKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { describe, expect, test } from "vitest";
import { kmsKeyWrapper } from "../src/index.js";

const ENDPOINT = process.env.AFR_KMS_ENDPOINT ?? "";

describe.skipIf(!ENDPOINT)("kmsKeyWrapper", () => {
  test("wraps a DEK bound to its org; another org's context can't unwrap it", async () => {
    const kms = new KMSClient({
      endpoint: ENDPOINT,
      region: "us-east-1",
      credentials: { accessKeyId: "test", secretAccessKey: "test" },
    });
    const key = await kms.send(new CreateKeyCommand({ Description: "afr test KEK" }));
    const kek = kmsKeyWrapper(kms, key.KeyMetadata?.KeyId as string);
    const dek = new Uint8Array(randomBytes(32));
    const wrapped = await kek.wrapDataKey(dek, "org-a");
    expect(Buffer.from(wrapped).includes(Buffer.from(dek))).toBe(false);
    expect(Buffer.from(await kek.unwrapDataKey(wrapped, "org-a"))).toEqual(Buffer.from(dek));
    await expect(kek.unwrapDataKey(wrapped, "org-b")).rejects.toThrow();
  });
});
