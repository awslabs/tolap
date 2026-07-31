/**
 * Every source module must load under Node's type stripping.
 *
 * The server runs its own `.ts` sources directly via
 * `node --experimental-strip-types`, which is **strip-only**: it erases type
 * annotations but performs no downlevelling. Syntax that needs desugaring --
 * constructor parameter properties, enums, namespaces, decorators -- typechecks
 * and passes vitest (which transpiles properly) yet throws
 * `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` the moment the real server starts.
 *
 * That gap is exactly what this test closes. It already caught two parameter
 * properties that `tsc` and the whole unit suite were happy with, so it earns its
 * keep: without it the first sign of trouble is a server that will not boot.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import path from "node:path";

const SRC = path.resolve(__dirname, "../src");

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...sourceFiles(full));
    } else if (entry.endsWith(".ts")) {
      found.push(full);
    }
  }
  return found.sort();
}

describe("Node type-stripping compatibility", () => {
  const files = sourceFiles(SRC);

  it("finds source files to check", () => {
    // A glob that silently matched nothing would make every assertion below
    // vacuous -- the failure mode this repo has been bitten by before.
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files.map((f) => path.relative(SRC, f)))(
    "%s loads under --experimental-strip-types",
    (relative) => {
      const full = path.join(SRC, relative);
      try {
        execFileSync(
          process.execPath,
          [
            "--experimental-strip-types",
            "--no-warnings",
            "-e",
            `import(${JSON.stringify(full)})`,
          ],
          { stdio: "pipe", encoding: "utf8" },
        );
      } catch (error) {
        const detail = (error as { stderr?: string }).stderr ?? String(error);
        throw new Error(`${relative} is not loadable by Node:\n${detail}`);
      }
    },
  );
});
