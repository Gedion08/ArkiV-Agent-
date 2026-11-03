import { privateKeyToAccount } from "viem/accounts";
import { expect, test } from "vitest";
import {
  buildHeader,
  hashHeader,
  localSigner,
  recoverRecordSigner,
  signRecord,
  ZERO_HASH,
} from "../src/index.js";
import { SESSION_KEY_ADDR, SESSION_KEY_PK, toolCall } from "./fixtures/headers.js";

test("noble signer matches viem signMessage({ raw }) and recovers", async () => {
  const signer = localSigner(SESSION_KEY_PK);
  expect(signer.address).toBe(SESSION_KEY_ADDR);
  const hash = hashHeader(buildHeader(toolCall(), { seq: 0n, prevHash: ZERO_HASH }));
  const sig = await signRecord(signer, hash);
  const viemSig = await privateKeyToAccount(SESSION_KEY_PK).signMessage({ message: { raw: hash } });
  expect(sig).toBe(viemSig);
  expect(sig).toMatch(/^0x[0-9a-f]{128}(1b|1c)$/);
  expect(await recoverRecordSigner(hash, sig)).toBe(SESSION_KEY_ADDR);
});

test("signatures over the raw digest differ from signatures over the hex string", async () => {
  const hash = hashHeader(buildHeader(toolCall(), { seq: 0n, prevHash: ZERO_HASH }));
  const asString = await privateKeyToAccount(SESSION_KEY_PK).signMessage({ message: hash });
  expect(localSigner(SESSION_KEY_PK).signDigest(hash)).not.toBe(asString);
});
