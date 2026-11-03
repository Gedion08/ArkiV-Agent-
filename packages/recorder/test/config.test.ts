import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { configHash, envName, loadConfig, parseConfig } from "../src/config.js";

const AGENT = "eip155:8453:0x00000000000000000000000000000000000a8004:42";
const minimal = { version: 1, agent: { id: AGENT } };

describe("P1-10 config", () => {
  test("minimal config gets documented defaults", () => {
    const c = parseConfig(minimal, {});
    expect(c.agent).toEqual({ id: AGENT, lane: 0, privacy_level: 0, retention_days: 365 });
    expect(c).toMatchObject({ data_dir: "~/.afr", durability: "normal", fail_mode: "open" });
    expect(c.capture.max_body_bytes).toBe(65536);
    expect(c.delegation.session_ttl_s).toBe(86400);
  });

  test("loads YAML from disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "afr-cfg-"));
    const f = join(dir, "afr.config.yaml");
    writeFileSync(
      f,
      `version: 1\nagent:\n  id: "${AGENT}"\n  lane: 2\nproxy:\n  upstreams:\n    - name: everything\n      command: npx -y @modelcontextprotocol/server-everything\n`,
    );
    const c = loadConfig(f, {});
    expect(c.agent.lane).toBe(2);
    expect(c.proxy?.upstreams[0]).toMatchObject({ name: "everything", forward_auth: false });
  });

  test("env vars override file values, with type coercion", () => {
    expect(envName(["agent", "id"])).toBe("AFR_AGENT_ID");
    const c = parseConfig(minimal, {
      AFR_AGENT_LANE: "3",
      AFR_STORE_KIND: "postgres",
      AFR_DATA_DIR: "/var/lib/afr",
      AFR_BATCH_HEARTBEAT: "false",
      AFR_AGENT_ID: "local:9b2f4e0a-1c3d-4e5f-8a6b-7c8d9e0f1a2b",
    });
    expect(c.agent).toMatchObject({ lane: 3, id: "local:9b2f4e0a-1c3d-4e5f-8a6b-7c8d9e0f1a2b" });
    expect(c.store.kind).toBe("postgres");
    expect(c.data_dir).toBe("/var/lib/afr");
    expect(c.batch?.heartbeat).toBe(false);
  });

  test.each([
    [{ version: 1 }, "agent"],
    [{ version: 2, agent: { id: AGENT } }, "version"],
    [{ ...minimal, agent: { id: "eip155:8453:0xABC:1" } }, "agent.id"],
    [{ ...minimal, durabilty: "strict" }, "Unrecognized key"],
    [{ ...minimal, delegation: { session_ttl_s: 999999 } }, "delegation.session_ttl_s"],
    [{ ...minimal, proxy: { upstreams: [{ name: "x" }] } }, "exactly one of command | url"],
  ])("invalid config %# gives a readable error mentioning %s", (raw, needle) => {
    expect(() => parseConfig(raw, {})).toThrow(
      expect.objectContaining({ code: "CONFIG_INVALID", message: expect.stringContaining(needle) }),
    );
  });

  test("bad YAML and missing file", () => {
    const dir = mkdtempSync(join(tmpdir(), "afr-cfg-"));
    writeFileSync(join(dir, "bad.yaml"), "agent: [unclosed");
    expect(() => loadConfig(join(dir, "bad.yaml"), {})).toThrow(
      expect.objectContaining({ code: "CONFIG_INVALID" }),
    );
    expect(() => loadConfig(join(dir, "nope.yaml"), {})).toThrow(
      expect.objectContaining({ code: "CONFIG_NOT_FOUND" }),
    );
  });

  test("config hash is stable across key order and changes with content", () => {
    const a = parseConfig({ agent: { id: AGENT, lane: 0 }, version: 1 }, {});
    const b = parseConfig({ version: 1, agent: { lane: 0, id: AGENT } }, {});
    expect(configHash(a)).toBe(configHash(b));
    expect(configHash(parseConfig({ ...minimal, fail_mode: "closed" }, {}))).not.toBe(
      configHash(a),
    );
  });
});
