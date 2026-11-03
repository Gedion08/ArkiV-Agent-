// Dev-only: run workspace TypeScript sources directly with Node's built-in type stripping
// (`node --import ./tools/ts/register.mjs file.ts`). Maps `./x.js` imports to `./x.ts` and
// resolves @afr/* packages to their sources. Used by crash tests that need a real child process.
import { register } from "node:module";

register(new URL("./hooks.mjs", import.meta.url));
