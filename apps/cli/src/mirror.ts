// fr mirror pull + fr verify agent --mirror FILE (P3 exit demo): an agent's Arkiv entities as JSON lines,
// loaded back into a MemoryStore. A mirror is untrusted like Arkiv itself: the verifier's signature,
// chain and anchor checks decide, and a mirror can forge `$creator`, so the writer filter is only
// discovery here too (CLAUDE.md rule 8).
import { readFileSync } from "node:fs";
import {
  type AfrSchemaName,
  type EvidenceStore,
  MemoryChain,
  MemoryStore,
  SCHEMA_NAMES,
  SCHEMA_SPEC,
  type StoredEntity,
} from "@afr/store";
import { bytesToHex, type Hex, hexToBytes } from "viem";

export const MIRROR_FORMAT = "afr-mirror/1";

interface Line {
  format: typeof MIRROR_FORMAT;
  key: Hex;
  schema: AfrSchemaName;
  attrs: Record<string, string | boolean>;
  payload: Hex;
  meta: { owner: Hex; creator: Hex; created_at_block: string; expires_at_block: string };
}

const attrSpec = (schema: AfrSchemaName) =>
  SCHEMA_SPEC[schema].attrs as Record<string, { type: string }>;
const PER_AGENT = SCHEMA_NAMES.filter((s) => "agent_key" in attrSpec(s));

/** Every entity of the agent in schemas keyed by agent_key, as JSON lines (all writers). */
export async function pullMirror(store: EvidenceStore, agentKey: Hex): Promise<string> {
  const lines: string[] = [];
  for (const schema of PER_AGENT)
    for await (const e of store.query({
      schema,
      where: { agent_key: { eq: agentKey } },
    } as never)) {
      const x = e as StoredEntity;
      const line: Line = {
        format: MIRROR_FORMAT,
        key: x.ref.key,
        schema,
        attrs: Object.fromEntries(
          Object.entries(x.attrs as Record<string, unknown>).map(([k, v]) => [
            k,
            typeof v === "bigint" ? v.toString() : (v as string | boolean),
          ]),
        ),
        payload: bytesToHex(x.payload),
        meta: {
          owner: x.meta.owner,
          creator: x.meta.creator,
          created_at_block: x.meta.createdAtBlock.toString(),
          expires_at_block: x.meta.expiresAtBlock.toString(),
        },
      };
      lines.push(JSON.stringify(line));
    }
  return lines.length ? `${lines.join("\n")}\n` : "";
}

export class MirrorError extends Error {}

/** Parses a mirror file into a read-only MemoryStore; malformed lines are an error, not skipped. */
export function loadMirror(file: string): EvidenceStore {
  const chain = new MemoryChain();
  let head = 0n;
  const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
  lines.forEach((text, i) => {
    const bad = (why: string) => new MirrorError(`mirror line ${i + 1}: ${why}`);
    let l: Line;
    try {
      l = JSON.parse(text) as Line;
    } catch {
      throw bad("not JSON");
    }
    if (l.format !== MIRROR_FORMAT) throw bad("unknown format");
    if (!SCHEMA_NAMES.includes(l.schema)) throw bad("unknown schema");
    if (!/^0x[0-9a-f]{64}$/i.test(l.key) || !/^0x([0-9a-f]{2})*$/i.test(l.payload))
      throw bad("bad key or payload");
    const spec = attrSpec(l.schema);
    const attrs: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(l.attrs ?? {})) {
      const t = spec[k]?.type;
      if (!t) throw bad(`unknown attribute ${k}`);
      if (t === "u64" && !(typeof v === "string" && /^\d{1,20}$/.test(v))) throw bad(`bad ${k}`);
      attrs[k] = t === "u64" ? BigInt(v as string) : v;
    }
    const num = (s: string) => {
      if (!/^\d{1,20}$/.test(s)) throw bad("bad block number");
      return BigInt(s);
    };
    const createdAtBlock = num(l.meta?.created_at_block);
    const row = {
      schema: l.schema,
      attrs,
      payload: hexToBytes(l.payload),
      owner: l.meta.owner,
      creator: l.meta.creator,
      createdAtBlock,
      expiresAtBlock: num(l.meta.expires_at_block),
      readonly: true,
      permissionlessExtension: false,
    };
    chain.rows.set(l.key.toLowerCase() as Hex, row);
    if (createdAtBlock > head) head = createdAtBlock;
  });
  // the clock sits just past the newest entity, so everything pulled is live
  chain.block = head + 1n;
  return new MemoryStore(chain, `0x${"00".repeat(20)}`);
}
