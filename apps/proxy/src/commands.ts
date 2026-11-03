// fr-proxy commands other than `run` (L2 §5.3).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { AfrError, assertAgentId } from "@afr/core";
import { parseConfig, verifyJournal } from "@afr/recorder";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { stringify } from "yaml";
import type { Resolved } from "./config.js";

type Out = (s: string) => void;

export interface InitOptions {
  out: string;
  agentId?: string;
  lane?: string;
  dataDir?: string;
  delegation?: string;
  upstream?: string;
  force?: boolean;
  interactive: boolean;
}

/** Writes afr.config.yaml. Missing values are asked for on a TTY; validated before writing. */
export async function init(o: InitOptions, print: Out): Promise<number> {
  if (existsSync(o.out) && !o.force) {
    print(`${o.out} exists; use --force to overwrite\n`);
    return 1;
  }
  const rl = o.interactive
    ? createInterface({ input: process.stdin, output: process.stderr })
    : undefined;
  const ask = async (q: string, dflt?: string) => {
    if (!rl) return dflt;
    const a = (await rl.question(`${q}${dflt ? ` [${dflt}]` : ""}: `)).trim();
    return a || dflt;
  };
  try {
    const agentId =
      o.agentId ?? (await ask("ERC-8004 agent id (eip155:<chain>:<registry>:<tokenId>)"));
    if (!agentId) throw new AfrError("CONFIG_INVALID", "agent id is required (--agent-id)");
    assertAgentId(agentId);
    const raw = {
      version: 1,
      agent: { id: agentId, lane: Number(o.lane ?? (await ask("lane", "0"))) },
      data_dir: o.dataDir ?? (await ask("data dir", "~/.afr")),
      delegation: {
        mode:
          o.delegation ??
          (await ask("delegation mode (operator_env | interactive)", "interactive")),
      },
      keystore: { kind: "dev-plaintext" },
      ...(o.upstream
        ? { proxy: { listen: "stdio", upstreams: [{ name: "upstream", command: o.upstream }] } }
        : {}),
    };
    parseConfig(raw, {}); // never write an invalid file
    writeFileSync(
      o.out,
      `# Agent Flight Recorder — see docs/02-layers/L2-capture-recorder.md §11\n${stringify(raw)}`,
      { mode: 0o600 },
    );
    print(`wrote ${o.out}\n`);
    return 0;
  } finally {
    rl?.close();
  }
}

export async function status(r: Resolved, print: Out): Promise<number> {
  const path = `${r.laneDir}/journal.sqlite`;
  const rep = await verifyJournal(path);
  const last = rep.sessions.at(-1);
  print(
    `${JSON.stringify(
      {
        agent_id: rep.agentId,
        lane: rep.lane,
        journal: path,
        records: rep.records,
        next_seq: rep.seqRange ? String(BigInt(rep.seqRange[1]) + 1n) : "0",
        session_key: last?.address ?? null,
        delegation: last?.delegation ?? null,
        pending_delegation_request:
          existsSync(`${r.laneDir}/delegation-request.json`) &&
          !existsSync(`${r.laneDir}/delegation.sig`),
        chain_ok: rep.ok,
      },
      null,
      2,
    )}\n`,
  );
  return rep.ok ? 0 : 1;
}

/**
 * Interactive delegation helper: prints the pending EIP-712 request, or answers it with --sig,
 * or (dev/operator_env) signs it with AFR_OPERATOR_KEY when --sign is given.
 */
export async function delegate(
  r: Resolved,
  o: { sig?: string; sign?: boolean },
  print: Out,
): Promise<number> {
  const reqPath = `${r.laneDir}/delegation-request.json`;
  if (!existsSync(reqPath)) {
    print(
      "no pending delegation request (start `fr-proxy run` with delegation.mode=interactive first)\n",
    );
    return 1;
  }
  let sig = o.sig;
  if (!sig && o.sign) {
    const key = r.env.AFR_OPERATOR_KEY;
    if (!key) throw new AfrError("OPERATOR_KEY_MISSING", "--sign needs AFR_OPERATOR_KEY");
    const { typedData } = JSON.parse(readFileSync(reqPath, "utf8"));
    const m = typedData.message;
    sig = await privateKeyToAccount(key as Hex).signTypedData({
      ...typedData,
      domain: { ...typedData.domain, chainId: BigInt(typedData.domain.chainId) },
      message: {
        ...m,
        notBefore: BigInt(m.notBefore),
        notAfter: BigInt(m.notAfter),
        nonce: BigInt(m.nonce),
      },
    });
  }
  if (!sig) {
    print(readFileSync(reqPath, "utf8"));
    print(
      "\nsign this EIP-712 payload with the agent owner's wallet, then run: fr-proxy delegate --sig 0x…\n",
    );
    return 0;
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig))
    throw new AfrError("DELEGATION_BAD_SIG", "signature must be 65 bytes hex");
  writeFileSync(`${r.laneDir}/delegation.sig`, sig, { mode: 0o600 });
  print("delegation signature handed to the recorder\n");
  return 0;
}
