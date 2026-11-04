import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Config, parseConfig } from "../../src/config.js";

export const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
export const OPERATOR_KEY = `0x${"00".repeat(31)}02` as const;
export const OPERATOR_ADDR = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf";

export function tmpConfig(over: Record<string, unknown> = {}): Config {
  const dir = mkdtempSync(join(tmpdir(), "afr-rec-"));
  return parseConfig(
    {
      version: 1,
      agent: { id: AGENT },
      data_dir: dir,
      delegation: { mode: "operator_env" },
      ...over,
    },
    {},
  );
}

export const env = { AFR_OPERATOR_KEY: OPERATOR_KEY };

/** Batches upload only after their delegation is published (L2 §9): wait for the signature first. */
export async function ready<R extends { delegationReady(): Promise<unknown> }>(
  p: Promise<R>,
): Promise<R> {
  const rec = await p;
  await rec.delegationReady();
  return rec;
}
