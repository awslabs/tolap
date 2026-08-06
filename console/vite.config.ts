// vitest/config rather than vite: it is the same defineConfig widened to accept
// the `test` block below, which vite's own types reject.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The admin API runs on its own listener. Proxying in dev keeps the console's
    // fetch calls same-origin so no CORS configuration is needed here or there --
    // in production the console is served as static files behind the same host.
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.tsx", "src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      reporter: ["text", "lcov"],
    },
  },
});
