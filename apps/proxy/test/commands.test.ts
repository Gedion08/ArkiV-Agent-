// P1-16: fr-proxy init / status / delegate (L2 §5.3), incl. the interactive delegation handshake.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileSignatureRequester, laneDir, loadConfig, parseConfig, Recorder } from "@afr/recorder";
import { describe, expect, test } from "vitest";
import { delegate, init, status } from "../src/commands.js";

const AGENT = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const OPERATOR_KEY = `0x${"00".repeat(31)}02`;
const tmp = () => mkdtempSync(join(tmpdir(), "afr-cmd-"));

function capture() {
  let out = "";
  return {
    print: (s: string) => {
      out += s;
    },
    text: () => out,
  };
}

describe("P1-16 commands", () => {
  test("init writes a config that loads; refuses to overwrite without --force", async () => {
    const dir = tmp();
    const out = join(dir, "afr.config.yaml");
    const o = { out, agentId: AGENT, dataDir: dir, delegation: "operator_env", interactive: false };
    expect(await init({ ...o, upstream: "node server.js" }, capture().print)).toBe(0);
    const cfg = loadConfig(out, {});
    expect(cfg.agent.id).toBe(AGENT);
    expect(cfg.proxy?.upstreams[0]?.command).toBe("node server.js");
    const c = capture();
    expect(await init(o, c.print)).toBe(1);
    expect(c.text()).toMatch(/exists/);
    expect(await init({ ...o, force: true }, capture().print)).toBe(0);
  });

  test("init without an agent id (non-interactive) fails and writes nothing", async () => {
    const out = join(tmp(), "afr.config.yaml");
    await expect(init({ out, interactive: false }, capture().print)).rejects.toMatchObject({
      code: "CONFIG_INVALID",
    });
    await expect(import("node:fs").then((f) => f.existsSync(out))).resolves.toBe(false);
  });

  test("interactive delegation: request file → delegate --sign → recorder gets the signature; status reports it", async () => {
    const config = parseConfig(
      { version: 1, agent: { id: AGENT }, data_dir: tmp(), delegation: { mode: "interactive" } },
      {},
    );
    const resolved = {
      config,
      env: { AFR_OPERATOR_KEY: OPERATOR_KEY },
      dev: false,
      laneDir: laneDir(config),
    };
    const rec = await Recorder.start({
      config,
      env: {},
      autoRotate: false,
      requestSignature: fileSignatureRequester(resolved.laneDir, { pollMs: 10, timeoutMs: 5000 }),
    });
    const shown = capture();
    expect(await delegate(resolved, {}, shown.print)).toBe(0);
    expect(shown.text()).toMatch(/"primaryType": "Delegation"/);
    expect(await delegate(resolved, { sign: true }, capture().print)).toBe(0);
    await rec.delegationReady();
    expect(rec.status().delegation).toBe("signed");
    await rec.close();

    const st = capture();
    expect(await status(resolved, st.print)).toBe(0);
    expect(JSON.parse(st.text())).toMatchObject({
      agent_id: AGENT,
      chain_ok: true,
      delegation: "signed",
      pending_delegation_request: false,
    });
  });

  test("delegate rejects a malformed --sig and reports no pending request", async () => {
    const config = parseConfig({ version: 1, agent: { id: AGENT }, data_dir: tmp() }, {});
    const resolved = { config, env: {}, dev: false, laneDir: laneDir(config) };
    const c = capture();
    expect(await delegate(resolved, { sig: "0x00" }, c.print)).toBe(1);
    expect(c.text()).toMatch(/no pending/);
  });
});
