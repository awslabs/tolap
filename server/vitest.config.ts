import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // The cross-SDK test shells out to python3 and dotnet, which are slower than
    // an in-process assertion. The default 5s timeout fails them on a cold
    // `dotnet run` even when the artifact is correct.
    testTimeout: 120_000,
    coverage: {
      provider: "v8",
      // Only this package's sources. The aliases below pull the SDK sources into
      // the module graph, and without this the report would mix SDK coverage in.
      include: ["src/**"],
      reporter: ["text", "lcov"],
    },
  },
  resolve: {
    alias: {
      "@aws/tolap-core": path.resolve(
        __dirname,
        "../sdk/typescript/packages/core/src/index.ts",
      ),
      "@aws/tolap-store": path.resolve(
        __dirname,
        "../sdk/typescript/packages/store/src/index.ts",
      ),
    },
  },
});
