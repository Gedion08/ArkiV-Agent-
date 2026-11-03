// R2 (L2 §15): kill -9 at random points; restart → no lost journaled record, chain valid, no duplicate seq.
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyRecords } from "@afr/core";
import { expect, test } from "vitest";
import { parseConfig } from "../src/config.js";
import { Recorder } from "../src/recorder.js";
import { AGENT, OPERATOR_KEY } from "./fixtures/setup.js";

// L2 R2 asks for 100 runs (CI sets AFR_CRASH_RUNS=100); 20 keeps the local unit suite fast
const RUNS = Number(process.env.AFR_CRASH_RUNS ?? 20);
const register = fileURLToPath(new URL("../../../tools/ts/register.mjs", import.meta.url));
const child = fileURLToPath(new URL("./fixtures/crash-child.ts", import.meta.url));

function runAndKill(dataDir: string, killAfterMs: number): Promise<bigint[]> {
  return new Promise((resolve, reject) => {
    const p = spawn(
      process.execPath,
      ["--no-warnings", "--import", register, child, dataDir, AGENT],
      {
        env: { ...process.env, AFR_OPERATOR_KEY: OPERATOR_KEY },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let out = "";
    let err = "";
    p.stdout.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.startsWith("ready\n") && !p.killed) setTimeout(() => p.kill("SIGKILL"), killAfterMs);
    });
    p.stderr.on("data", (d: Buffer) => {
      err += d.toString();
    });
    p.on("exit", (code, signal) => {
      if (signal !== "SIGKILL")
        return reject(new Error(`child exited ${code}: ${err.slice(0, 500)}`));
      // the last line may be cut mid-write by the kill; only complete lines are acknowledgements
      const lines = out.split("\n").slice(1, -1);
      resolve(lines.map((l) => BigInt(l)));
    });
  });
}

test(`R2: ${RUNS} SIGKILLs at random points never lose or duplicate a journaled record`, async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "afr-crash-"));
  const acked = new Set<bigint>();
  for (let run = 0; run < RUNS; run++) {
    for (const s of await runAndKill(dataDir, Math.floor(Math.random() * 40))) {
      expect(acked.has(s)).toBe(false); // a seq is never handed out twice across restarts
      acked.add(s);
    }
  }
  const config = parseConfig(
    { version: 1, agent: { id: AGENT }, data_dir: dataDir, delegation: { mode: "operator_env" } },
    {},
  );
  const rec = await Recorder.start({
    config,
    env: { AFR_OPERATOR_KEY: OPERATOR_KEY },
    autoRotate: false,
  });
  const records = [...rec.journal.iterate()].map((r) => ({
    header: r.header,
    sig: r.sig,
    hash: r.hash,
  }));
  const seqs = new Set(records.map((r) => BigInt(r.header.seq)));
  for (const s of acked) expect(seqs.has(s)).toBe(true);
  expect(await verifyRecords(records)).toEqual([]);
  expect(records.filter((r) => r.header.type === "session_start").length).toBe(RUNS + 1);
  await rec.close();
}, 600_000);
