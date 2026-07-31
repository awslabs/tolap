/**
 * Serializes `dotnet` invocations across test files.
 *
 * Two test files stand up a throwaway console project that `ProjectReference`s the real
 * `sdk/dotnet/src/Tolap.Core/Tolap.Core.csproj`. Vitest runs test files in parallel, so
 * both MSBuild processes end up writing that one project's `obj/` at the same time —
 * `project.assets.json`, the generated `.AssemblyInfo.cs`, the nuget props. When they
 * interleave, one build reads a half-written intermediate and fails with a bare
 *
 *     The build failed. Fix the build errors and run again.
 *
 * which reads like the SDK is broken rather than like a test-harness collision. It is
 * timing-dependent, so it shows up on a cold `obj/` — which is every CI run — and not on
 * a warm local one.
 *
 * The lock is a directory, because `mkdir` is atomic on every platform we run on and
 * needs no cleanup handler to be correct: a stale lock past the deadline is broken open
 * rather than deadlocking the suite.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const LOCK_DIR = path.join(tmpdir(), "tolap-dotnet-build.lock");

/** Longest a single `dotnet run` may hold the lock before it is presumed dead. */
const STALE_MS = 240_000;

/** How long to wait for the lock before giving up and letting the test fail loudly. */
const ACQUIRE_TIMEOUT_MS = 300_000;

function sleep(ms: number): void {
  // Blocking on purpose: the tests that need this are synchronous, and an async variant
  // would release the event loop and let a second test file start its build anyway.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function acquire(): void {
  const deadline = Date.now() + ACQUIRE_TIMEOUT_MS;
  for (;;) {
    try {
      mkdirSync(LOCK_DIR);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;

      // A crashed run must not wedge the suite forever.
      try {
        if (Date.now() - statSync(LOCK_DIR).mtimeMs > STALE_MS) {
          rmSync(LOCK_DIR, { recursive: true, force: true });
          continue;
        }
      } catch {
        // Vanished between the EEXIST and the stat; the next mkdir will win it.
      }

      if (Date.now() > deadline) {
        throw new Error(
          `timed out waiting for ${LOCK_DIR}; remove it if no dotnet build is running`,
        );
      }
      sleep(250);
    }
  }
}

/**
 * Runs `fn` with the shared-project build lock held.
 *
 * Exported so the serialization property can be tested directly; `runDotnet` is the only
 * production caller.
 */
export function withBuildLock<T>(fn: () => T): T {
  acquire();
  try {
    return fn();
  } finally {
    rmSync(LOCK_DIR, { recursive: true, force: true });
  }
}

/**
 * Runs `dotnet` with the shared-project build serialized.
 *
 * Returns stdout. Errors propagate unchanged so a genuine build or verification failure
 * still surfaces as itself.
 */
export function runDotnet(args: string[], cwd: string): string {
  return withBuildLock(() =>
    execFileSync("dotnet", args, {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }),
  );
}
