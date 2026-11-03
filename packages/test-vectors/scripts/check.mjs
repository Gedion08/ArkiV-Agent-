// Shape check for vector files. Immutability is enforced in CI against main (see ci.yml).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../vectors/", import.meta.url));
const files = readdirSync(dir, { recursive: true }).filter((f) => String(f).endsWith(".json"));
for (const f of files) {
  const v = JSON.parse(readFileSync(join(dir, String(f)), "utf8"));
  if (
    typeof v.format !== "string" ||
    !Number.isInteger(v.version) ||
    !Array.isArray(v.cases) ||
    !v.cases.length
  ) {
    throw new Error(`${f}: expected { format, version, cases[≥1] }`);
  }
}
console.log(`test-vectors: ${files.length} file(s) ok`);
