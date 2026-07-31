import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Scoped to this package. Without it vitest walks up and collects the server's
    // suites, which then run against the wrong working directory.
    include: ["test/**/*.test.ts"],
    root: import.meta.dirname,
    // Synthesizing five stacks is slower than a unit test, and the first synth pays
    // for CDK's module load.
    testTimeout: 60_000,
  },
});
