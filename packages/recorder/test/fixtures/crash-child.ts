// Child process for the R2 crash test: start (recovering), then capture until killed.
import { parseConfig } from "../../src/config.js";
import { Recorder } from "../../src/recorder.js";

const [dataDir, agent] = process.argv.slice(2) as [string, string];
const config = parseConfig(
  { version: 1, agent: { id: agent }, data_dir: dataDir, delegation: { mode: "operator_env" } },
  {},
);
const rec = await Recorder.start({ config, autoRotate: false });
process.stdout.write("ready\n");
for (let i = 0; ; i++) {
  const { seq, record } = rec.capture({
    type: i % 2 ? "tool_result" : "tool_call",
    ...(i % 2 ? { refSeq: rec.status().nextSeq - 1n } : {}),
    tool: { server: "everything", name: "echo" },
    body: i % 2 ? { result: { content: [{ type: "text", text: `r${i}` }] } } : { args: { i } },
  });
  // acknowledged = journaled; the parent checks every acknowledged seq survives the kill
  if (record) process.stdout.write(`${seq}\n`);
  if (i % 7 === 0) await new Promise((r) => setImmediate(r));
}
