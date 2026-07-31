import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      // Only the shipped sources count. Including tests or config files would
      // inflate the number with files whose coverage says nothing about the SDK.
      include: ["src/**"],
      reporter: ["text", "lcov"],
    },
  },
});
