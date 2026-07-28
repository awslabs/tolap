import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@tolap/core": path.resolve(__dirname, "../core/src/index.ts"),
    },
  },
});
