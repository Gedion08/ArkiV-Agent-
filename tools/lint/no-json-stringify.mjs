// CLAUDE.md rule 5: hashed formats use jcs(), never JSON.stringify.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const TARGETS = ["packages/core/src/record", "packages/store/src/frame.ts"];

function* files(path) {
  let st;
  try {
    st = statSync(path);
  } catch {
    return; // target not created yet
  }
  if (st.isFile()) yield path;
  else for (const e of readdirSync(path)) yield* files(join(path, e));
}

const hits = [];
for (const t of TARGETS) {
  for (const f of files(t)) {
    readFileSync(f, "utf8")
      .split("\n")
      .forEach((line, i) => {
        if (/\bJSON\s*\.\s*stringify\b/.test(line)) hits.push(`${f}:${i + 1}: ${line.trim()}`);
      });
  }
}
if (hits.length) {
  console.error(`JSON.stringify is banned in hashed-format code; use jcs():\n${hits.join("\n")}`);
  process.exit(1);
}
console.log("no-json-stringify: ok");
