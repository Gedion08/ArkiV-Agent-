// Journal key storage (L2 §4 "Journal key"). P1 implements dev-plaintext only.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { AfrError } from "@afr/core";
import type { Logger } from "@afr/log";
import type { Config } from "./config.js";

/** Loads or creates the 32-byte journal key. */
export function loadJournalKey(
  keystore: Config["keystore"],
  keyPath: string,
  log?: Logger,
): Uint8Array {
  if (keystore.kind !== "dev-plaintext") {
    // shortcut: KMS/OS/passphrase keystores are not built yet; land with production deploys (P6/P7)
    throw new AfrError(
      "KEYSTORE_UNSUPPORTED",
      `keystore.kind=${keystore.kind} is not implemented yet; use dev-plaintext`,
    );
  }
  log?.warn(
    { keyPath },
    "dev-plaintext keystore: journal key stored unencrypted on disk (dev only)",
  );
  if (existsSync(keyPath)) {
    const hex = readFileSync(keyPath, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex))
      throw new AfrError("KEYSTORE_CORRUPT", "journal key file is not 32 bytes hex");
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
  const key = randomBytes(32);
  writeFileSync(keyPath, key.toString("hex"), { mode: 0o600, flag: "wx" });
  return new Uint8Array(key);
}
