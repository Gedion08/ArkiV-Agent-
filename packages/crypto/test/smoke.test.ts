import { expect, test } from "vitest";
import { aesGcmOpen, aesGcmSeal, PACKAGE_NAME } from "../src/index.js";

const key = new Uint8Array(32).fill(7);
const iv = new Uint8Array(12).fill(1);
const aad = new TextEncoder().encode("aad");
const pt = new TextEncoder().encode("secret body");

test("package loads", () => expect(PACKAGE_NAME).toBe("@afr/crypto"));

test("AES-GCM round-trips and authenticates key, iv, aad and ciphertext", () => {
  const ct = aesGcmSeal(key, iv, pt, aad);
  expect(ct.length).toBe(pt.length + 16);
  expect(aesGcmOpen(key, iv, ct, aad)).toEqual(pt);
  const bad = ct.slice();
  bad[0] = (bad[0] ?? 0) ^ 1;
  for (const f of [
    () => aesGcmOpen(key, iv, bad, aad),
    () => aesGcmOpen(new Uint8Array(32), iv, ct, aad),
    () => aesGcmOpen(key, new Uint8Array(12), ct, aad),
    () => aesGcmOpen(key, iv, ct, new Uint8Array(0)),
  ]) {
    expect(f).toThrow(expect.objectContaining({ code: "DECRYPT_FAILED" }));
  }
  expect(() => aesGcmSeal(new Uint8Array(16), iv, pt, aad)).toThrow(
    expect.objectContaining({ code: "INVALID_KEY" }),
  );
});
