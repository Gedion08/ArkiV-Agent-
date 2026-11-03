// afr.config.yaml loader (L2 §11): zod schema, env overrides, config hash.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { AfrError, assertAgentId, keccakJcsData, LIMITS } from "@afr/core";
import type { Hex } from "viem";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const port = z.string().regex(/^(stdio|[0-9a-z.:[\]-]+:\d{1,5})$/, "stdio or host:port");

export const ConfigSchema = z.strictObject({
  version: z.literal(1),
  agent: z.strictObject({
    id: z.string().refine((s) => {
      try {
        assertAgentId(s);
        return true;
      } catch {
        return false;
      }
    }, "must be eip155:<chainId>:<0xregistry lowercase>:<tokenId> or local:<uuid-v4>"),
    lane: z
      .number()
      .int()
      .min(0)
      .max(2 ** 31 - 1)
      .default(0),
    privacy_level: z.union([z.literal(0), z.literal(1), z.literal(2)]).default(0),
    retention_days: z.number().int().positive().default(365),
  }),
  data_dir: z.string().default("~/.afr"),
  durability: z.enum(["normal", "strict"]).default("normal"),
  fail_mode: z.enum(["open", "closed"]).default("open"),
  store: z
    .strictObject({
      kind: z.enum(["arkiv", "postgres", "memory"]).default("memory"),
      arkiv: z
        .strictObject({
          chain: z.string().default("rabdi"),
          access_key_env: z.string().default("ARKIV_ACCESS_KEY"),
          writer_key_env: z.string().default("AFR_ARKIV_WRITER_KEY"),
          evidence_lock: z.boolean().default(true),
          expiry: z.enum(["upfront", "rolling"]).default("upfront"),
        })
        .optional(),
      postgres: z.strictObject({ url_env: z.string() }).optional(),
      mirror: z.enum(["postgres"]).optional(),
    })
    .default({ kind: "memory" }),
  delegation: z
    .strictObject({
      mode: z.enum(["operator_env", "kms", "identity_key", "interactive"]).default("identity_key"),
      session_ttl_s: z
        .number()
        .int()
        .min(600)
        .max(LIMITS.SESSION_KEY_MAX_TTL_S)
        .default(LIMITS.SESSION_KEY_MAX_TTL_S),
      kms: z.strictObject({ provider: z.enum(["aws", "gcp"]), key_id: z.string() }).optional(),
      identity_keystore: z.string().optional(),
      timeout_s: z.number().int().positive().default(600),
    })
    .default({ mode: "identity_key", session_ttl_s: LIMITS.SESSION_KEY_MAX_TTL_S, timeout_s: 600 }),
  keystore: z
    .strictObject({
      kind: z
        .enum(["aws-kms", "gcp-kms", "os", "passphrase", "dev-plaintext"])
        .default("dev-plaintext"),
      key_id: z.string().optional(),
    })
    .default({ kind: "dev-plaintext" }),
  encryption: z
    .strictObject({
      readers: z
        .array(z.string().regex(/^0x[0-9a-f]{64}$/, "x25519 public key, 32 bytes lowercase hex"))
        .default([]),
      epoch: z.literal("monthly").default("monthly"),
    })
    .default({ readers: [], epoch: "monthly" }),
  capture: z
    .strictObject({
      context: z.enum(["full", "hash_only", "last_turn"]).default("full"),
      max_body_bytes: z
        .number()
        .int()
        .min(1024)
        .max(LIMITS.BATCH_TARGET_BYTES)
        .default(LIMITS.MAX_BODY_BYTES_DEFAULT),
      binary: z.enum(["hash", "full"]).default("hash"),
    })
    .default({ context: "full", max_body_bytes: LIMITS.MAX_BODY_BYTES_DEFAULT, binary: "hash" }),
  batch: z
    .strictObject({
      max_age_ms: z.number().int().positive().default(LIMITS.BATCH_MAX_AGE_MS),
      target_bytes: z
        .number()
        .int()
        .positive()
        .max(LIMITS.BATCH_TARGET_BYTES)
        .default(LIMITS.BATCH_TARGET_BYTES),
      heartbeat: z.boolean().default(true),
      heartbeat_ms: z.number().int().positive().default(LIMITS.HEARTBEAT_MS),
      padding: z.boolean().default(true),
    })
    .optional(),
  api: z
    .strictObject({
      url: z.url(),
      key_env: z.string().default("AFR_API_KEY"),
      sync_readers: z.boolean().default(true),
    })
    .optional(),
  proxy: z
    .strictObject({
      listen: port.default("stdio"),
      /** Env var holding the bearer token HTTP clients must send; required for non-loopback binds. */
      auth_token_env: z.string().optional(),
      upstreams: z
        .array(
          z
            .strictObject({
              name: z.string().regex(/^[a-z0-9_-]{1,64}$/),
              command: z.string().optional(),
              url: z.url().optional(),
              forward_auth: z.boolean().default(false),
            })
            .refine(
              (u) => (u.command === undefined) !== (u.url === undefined),
              "exactly one of command | url",
            ),
        )
        .default([]),
    })
    .optional(),
  redact: z.array(z.unknown()).default([]),
  policy: z.strictObject({ file: z.string() }).optional(),
  journal: z
    .strictObject({
      retain_days: z.number().int().positive().default(30),
      max_bytes: z
        .number()
        .int()
        .positive()
        .default(10 * 1024 ** 3),
    })
    .default({ retain_days: 30, max_bytes: 10 * 1024 ** 3 }),
  archive: z.strictObject({ target: z.string() }).optional(),
  telemetry: z
    .strictObject({
      prometheus: z.string().optional(),
      otlp_endpoint: z.string().nullable().optional(),
    })
    .optional(),
});

export type Config = z.infer<typeof ConfigSchema>;

/** Leaf paths of the schema (for env overrides), with the leaf's scalar kind. */
function leaves(
  schema: z.ZodType,
  path: string[] = [],
  out: [string[], string][] = [],
): [string[], string][] {
  // biome-ignore lint/suspicious/noExplicitAny: walking zod's internal def tree
  const def = (schema as any)._zod.def;
  switch (def.type) {
    case "optional":
    case "default":
    case "nullable":
      return leaves(def.innerType, path, out);
    case "pipe":
      return leaves(def.in, path, out);
    case "object":
      for (const [k, v] of Object.entries(def.shape)) leaves(v as z.ZodType, [...path, k], out);
      return out;
    case "number":
    case "boolean":
    case "string":
    case "enum":
    case "literal":
    case "union":
      out.push([path, def.type]);
      return out;
    default:
      return out; // arrays/records: not overridable from env
  }
}

const ENV_LEAVES = leaves(ConfigSchema).filter(([p]) => p[0] !== "version");

/** AFR_<PATH>: agent.id → AFR_AGENT_ID, store.kind → AFR_STORE_KIND, data_dir → AFR_DATA_DIR. */
export function envName(path: string[]): string {
  return `AFR_${path.join("_").toUpperCase()}`;
}

function applyEnv(raw: Record<string, unknown>, env: NodeJS.ProcessEnv): Record<string, unknown> {
  const out = structuredClone(raw);
  for (const [path, kind] of ENV_LEAVES) {
    const v = env[envName(path)];
    if (v === undefined) continue;
    let cur = out;
    for (const p of path.slice(0, -1)) {
      if (typeof cur[p] !== "object" || cur[p] === null) cur[p] = {};
      cur = cur[p] as Record<string, unknown>;
    }
    const leaf = path.at(-1) as string;
    // literal/union leaves (version, privacy_level) are numeric in this schema
    if (kind === "boolean") cur[leaf] = v === "true";
    else if (kind === "number" || ((kind === "union" || kind === "literal") && /^\d+$/.test(v)))
      cur[leaf] = Number(v);
    else cur[leaf] = v;
  }
  return out;
}

function describe(issues: readonly { path: readonly PropertyKey[]; message: string }[]): string {
  return issues
    .map((i) => `  - ${i.path.map(String).join(".") || "<root>"}: ${i.message}`)
    .join("\n");
}

/** Parses and validates a config object (YAML already parsed). Env vars override file values. */
export function parseConfig(raw: unknown, env: NodeJS.ProcessEnv = process.env): Config {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AfrError("CONFIG_INVALID", "config must be a YAML mapping");
  }
  const r = ConfigSchema.safeParse(applyEnv(raw as Record<string, unknown>, env));
  if (!r.success)
    throw new AfrError("CONFIG_INVALID", `invalid afr config:\n${describe(r.error.issues)}`);
  return r.data;
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): Config {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new AfrError("CONFIG_NOT_FOUND", `cannot read config file ${path}`, { cause: e });
  }
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (e) {
    throw new AfrError(
      "CONFIG_INVALID",
      `config file ${path} is not valid YAML: ${(e as Error).message}`,
    );
  }
  return parseConfig(raw, env);
}

/** keccak(JCS(config)). The config holds env var NAMES, never secret values. */
export function configHash(config: Config): Hex {
  return keccakJcsData(config);
}

export function expandHome(p: string): string {
  return p === "~" || p.startsWith("~/") ? `${homedir()}${p.slice(1)}` : p;
}
