import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      // Only this package's shipped sources count. The @tolap/core alias below
      // pulls core's src into the module graph, and without this include the
      // report would mix core's coverage into the store numbers.
      include: ["src/**"],
      reporter: ["text", "lcov"],
    },
  },
  resolve: {
    alias: {
      "@tolap/core": path.resolve(__dirname, "../core/src/index.ts"),
    },
  },
});
