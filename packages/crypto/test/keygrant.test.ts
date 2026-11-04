// L4 §5 keygrants (K4) and §6 reader backups (K6).
import { Aes128Gcm, CipherSuite } from "@hpke/core";
import { DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/dhkem-x25519";
import { bytesToHex, type Hex, hexToBytes } from "viem";
import { describe, expect, test } from "vitest";
import {
  exportReaderBackup,
  generateReaderKey,
  importReaderBackup,
  newEpochKek,
  openKeygrant,
  sealKeygrant,
} from "../src/index.js";

const AK = `0x${"a1".repeat(32)}` as Hex;
const FAST = { m: 64, t: 1, p: 1 }; // test-only KDF cost

const code = (p: Promise<unknown>) =>
  p.then(
    () => "ok",
    (e: { code?: string }) => e.code,
  );

describe("K4 HPKE", () => {
  test("RFC 9180 A.1 (DHKEM(X25519)/HKDF-SHA256, base mode): our KEM + KDF give the published bytes", async () => {
    // A.1.1 uses AES-128-GCM; ours is AES-256-GCM (0x0002) on the same KEM/KDF.
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    const kpR = await suite.kem.deriveKeyPair(
      hexToBytes("0x6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"),
    );
    const r = await suite.seal(
      {
        recipientPublicKey: kpR.publicKey,
        info: hexToBytes("0x4f6465206f6e2061204772656369616e2055726e"),
        ekm: hexToBytes("0x7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"),
      },
      hexToBytes("0x4265617574792069732074727574682c20747275746820626561757479"),
      hexToBytes("0x436f756e742d30"),
    );
    expect(bytesToHex(new Uint8Array(r.enc))).toBe(
      "0x37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    );
    expect(bytesToHex(new Uint8Array(r.ct))).toBe(
      "0xf938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
    );
  });

  test("seal → open returns the KEK; another reader, epoch, kek_id or agent can't open it", async () => {
    const reader = await generateReaderKey();
    const other = await generateReaderKey();
    const kek = newEpochKek(AK, 352);
    const g = await sealKeygrant(kek, reader.pub, AK);
    expect([g.enc.length, g.ct.length]).toEqual([32, 48]);
    const grant = { ...g, epochId: 352, kekId: kek.kekId };
    const opened = await openKeygrant(grant, reader.priv, AK);
    expect(opened).toEqual({ ...kek, kekId: kek.kekId.toLowerCase() });

    expect(await code(openKeygrant(grant, other.priv, AK))).toBe("HPKE_OPEN_FAILED");
    expect(await code(openKeygrant({ ...grant, epochId: 353 }, reader.priv, AK))).toBe(
      "HPKE_OPEN_FAILED",
    );
    const otherKek = newEpochKek(AK, 352).kekId;
    expect(await code(openKeygrant({ ...grant, kekId: otherKek }, reader.priv, AK))).toBe(
      "HPKE_OPEN_FAILED",
    );
    const otherAgent = `0x${"b2".repeat(32)}` as Hex;
    expect(await code(openKeygrant(grant, reader.priv, otherAgent))).toBe("HPKE_OPEN_FAILED");
    expect(await code(openKeygrant({ ...grant, ct: g.ct.slice(1) }, reader.priv, AK))).toBe(
      "HPKE_OPEN_FAILED",
    );
  });

  test("a grant whose KEK doesn't match its kek_id is refused (KEK_ID_MISMATCH)", async () => {
    const reader = await generateReaderKey();
    const kek = newEpochKek(AK, 352);
    const lie = { ...kek, kekId: newEpochKek(AK, 352).kekId }; // sealed under a kek_id that isn't its own
    const g = await sealKeygrant(lie, reader.pub, AK);
    expect(
      await code(openKeygrant({ ...g, epochId: 352, kekId: lie.kekId }, reader.priv, AK)),
    ).toBe("KEK_ID_MISMATCH");
  });

  test("a malformed reader key is INVALID_KEY", async () => {
    expect(await code(sealKeygrant(newEpochKek(AK, 1), "0x1234", AK))).toBe("INVALID_KEY");
  });
});

describe("K6 .afrkey backup", () => {
  test("round trip; wrong passphrase → BACKUP_PASSPHRASE; the key never appears in the file", async () => {
    const r = await generateReaderKey();
    const file = await exportReaderBackup(r, "correct horse battery staple", FAST);
    expect(file).toMatchObject({ v: 1, kdf: "argon2id", x25519_pub: r.pub, ...FAST });
    expect(JSON.stringify(file)).not.toContain(bytesToHex(r.priv).slice(2));
    const back = await importReaderBackup(
      JSON.parse(JSON.stringify(file)),
      "correct horse battery staple",
    );
    expect(back).toEqual(r);
    expect(await code(importReaderBackup(file, "wrong"))).toBe("BACKUP_PASSPHRASE");
  });

  test("defaults are the L4 §6 parameters", async () => {
    const r = await generateReaderKey();
    const file = await exportReaderBackup(r, "pw");
    expect([file.m, file.t, file.p]).toEqual([65536, 3, 1]);
  }, 60_000);

  test("a swapped public key, malformed files and absurd KDF costs are refused", async () => {
    const r = await generateReaderKey();
    const file = await exportReaderBackup(r, "pw", FAST);
    const other = (await generateReaderKey()).pub;
    expect(await code(importReaderBackup({ ...file, x25519_pub: other }, "pw"))).toBe(
      "INVALID_KEY",
    );
    for (const bad of [
      null,
      "x",
      { ...file, v: 2 },
      { ...file, kdf: "scrypt" },
      { ...file, m: 1 << 30 },
      { ...file, t: 0 },
      { ...file, salt: "0x00" },
      { ...file, ct: `${file.ct}00` },
    ])
      expect(await code(importReaderBackup(bad, "pw"))).toBe("INVALID_KEY");
  });
});
