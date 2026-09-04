import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Files run one at a time, because five of the integration files each open their
    // `beforeAll` with `DROP TABLE ... CASCADE` from the shared `schema.sql` against the
    // same database. Run in parallel (vitest's default) they drop each other's tables
    // mid-run: `postgres-query-rewrite` adds a `nickname` column, a sibling recreates
    // `patients` without it, and the first file's queries then fail with
    // `column "nickname" does not exist`.
    //
    // It reads as a flake because it is a race, and it only appears when Postgres is
    // actually reachable -- with no database the files skip and the suite is green, which
    // is why it survived. The unit files cost ~2s serially, so this is cheap.
    fileParallelism: false,
    coverage: {
      provider: "v8",
      // Only this package's shipped sources count. The @aws/tolap-core alias below
      // pulls core's src into the module graph, and without this include the
      // report would mix core's coverage into the mcp numbers.
      include: ["src/**"],
      reporter: ["text", "lcov"],
    },
  },
  resolve: {
    alias: {
      "@aws/tolap-core": path.resolve(__dirname, "../core/src/index.ts"),
    },
  },
});
