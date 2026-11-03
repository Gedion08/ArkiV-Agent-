import { defineConfig } from "vitest/config";

export const config = defineConfig({
  // workspace packages resolve to src/ in tests (node tests run through Vite SSR resolution)
  resolve: { conditions: ["@afr/source"] },
  ssr: { resolve: { conditions: ["@afr/source"] } },
  test: { include: ["test/**/*.test.ts"], passWithNoTests: false },
});

export default config;
