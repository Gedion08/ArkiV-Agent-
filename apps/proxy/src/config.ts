// Config resolution shared by fr-proxy commands: --config file, or a persisted dev identity.
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { type Config, expandHome, laneDir, loadConfig, parseConfig } from "@afr/recorder";

export interface Resolved {
  config: Config;
  env: NodeJS.ProcessEnv;
  dev: boolean;
  laneDir: string;
}

/** Dev quick mode: local agent id + generated operator key, persisted so the chain continues across runs. */
function devConfig(env: NodeJS.ProcessEnv): { config: Config; env: NodeJS.ProcessEnv } {
  const dir = expandHome(env.AFR_DATA_DIR ?? "~/.afr");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const read = (file: string, make: () => string) => {
    const p = `${dir}/${file}`;
    if (!existsSync(p)) writeFileSync(p, make(), { mode: 0o600, flag: "wx" });
    return readFileSync(p, "utf8").trim();
  };
  const agentId = read("dev-agent-id", () => `local:${randomUUID()}`);
  const operatorKey = read("dev-operator.key", () => `0x${randomBytes(32).toString("hex")}`);
  return {
    config: parseConfig(
      { version: 1, agent: { id: agentId }, data_dir: dir, delegation: { mode: "operator_env" } },
      env,
    ),
    env: { ...env, AFR_OPERATOR_KEY: env.AFR_OPERATOR_KEY ?? operatorKey },
  };
}

export function resolveConfig(configPath: string | undefined, env: NodeJS.ProcessEnv): Resolved {
  const r = configPath ? { config: loadConfig(configPath, env), env } : devConfig(env);
  return { ...r, dev: !configPath, laneDir: laneDir(r.config) };
}
