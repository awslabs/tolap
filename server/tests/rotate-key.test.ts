/**
 * The rotation helper.
 *
 * Worth testing rather than treating as a script, because its whole job is to be trusted at
 * the one step of a rotation that is hard to undo. Step 4 drops the old key; if the tool
 * says a keyring is fine and it is not, every artifact still in flight becomes unverifiable
 * and enforcement fails closed — a broad denial across every tool the affected installs
 * wrap, with an error that does not name the cause.
 *
 * A checker that only ever passes is the specific failure to guard against here, so the
 * assertions below include the cases where it must FAIL: a keyring whose entries share a
 * secret (a rotation that looks complete and changed nothing), and the negative control
 * proving verification is actually running.
 *
 * Driven as a subprocess rather than by importing the module, because the tool calls
 * `process.exit` and its exit code is part of its contract — it is meant to be usable in a
 * script that gates a deploy.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import path from "node:path";

const TOOL = path.resolve(import.meta.dirname, "../tools/rotate-key.ts");

/** 40 chars, past the 32-character minimum. Distinct per label so keys differ. */
const secretFor = (label: string): string => label.repeat(40).slice(0, 40);

interface Run {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function run(...args: string[]): Run {
  try {
    const stdout = execFileSync(
      "node",
      ["--experimental-strip-types", TOOL, ...args],
      { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
    );
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return {
      status: failure.status ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

describe("generate", () => {
  it("mints a key past the configured minimum and prints both variables", () => {
    const result = run("generate", "--kid", "2026-08");
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("TOLAP_SIGNING_KEYS=");
    expect(result.stdout).toContain("TOLAP_ACTIVE_KID=");

    const secret = /2026-08:([A-Za-z0-9_-]+)"/.exec(result.stdout)?.[1];
    expect(secret, result.stdout).toBeDefined();
    // 32 random bytes as base64url. The config floor is 32 characters; a passphrase-length
    // secret here would be the weakest part of an otherwise sound signing scheme.
    expect(secret!.length).toBeGreaterThanOrEqual(43);
  });

  it("keeps the current key active, so generating one changes nothing yet", () => {
    // Step 1 adds a key; step 3 flips to it. A tool that printed the new kid as active
    // would turn "generate a key" into "rotate now", before consumers hold it.
    const result = run("generate", "--kid", "2026-08");
    expect(result.stdout).toMatch(/TOLAP_ACTIVE_KID=<current-kid>/);
    expect(result.stdout).toMatch(/flip to 2026-08 at step 3/);
  });

  it("refuses a kid containing a separator", () => {
    // A spec is `kid:secret` pairs split on the FIRST colon and separated by commas, so a
    // kid containing either silently truncates or splits into nonsense.
    for (const kid of ["has:colon", "has,comma"]) {
      const result = run("generate", "--kid", kid);
      expect(result.status, kid).toBe(2);
      expect(result.stderr).toMatch(/must not contain/);
    }
  });

  it("defaults the kid to a date rather than a counter", () => {
    // `key2` tells an operator nothing during an incident; a rotation is a dated event.
    const result = run("generate");
    expect(result.stdout).toMatch(/TOLAP_SIGNING_KEYS="<current-kid>:<current-secret>,\d{4}-\d{2}:/);
  });
});

describe("verify", () => {
  it("accepts a single-key ring and says when that is safe", () => {
    const result = run("verify", `solo:${secretFor("s")}`);
    expect(result.status).toBe(0);
    // The state after step 4. Safe only once a full TTL has elapsed, which the tool has no
    // way to check — so it says so rather than implying approval.
    expect(result.stdout).toMatch(/only safe at step 4/);
  });

  it("accepts a two-key overlap and states what the overlap does NOT do", () => {
    const result = run(
      "verify",
      `2026-05:${secretFor("o")},2026-08:${secretFor("n")}`,
    );
    expect(result.status).toBe(0);
    // The correction that matters. HMAC is symmetric, so only the signing key verifies --
    // an install holding just the old key cannot verify a new-key artifact. The docs
    // previously claimed "both keys verify throughout", which is false and would lead an
    // operator to flip the active kid before consumers hold the new key.
    expect(result.stdout).toMatch(/ONLY the\s+signing key verifies/);
    expect(result.stdout).toMatch(/before the active\s+kid flips/);
  });

  it("signs under the active key, including when it is not the first listed", () => {
    const result = run(
      "verify",
      `old:${secretFor("o")},new:${secretFor("n")}`,
      "--active",
      "new",
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/signed\s+kid=new/);
    expect(result.stdout).toMatch(/active\s+new/);
  });

  it("fails when two entries share a secret", () => {
    // A rotation that looks complete and changed nothing: the "new" key verifies artifacts
    // signed by the "old" one because they are the same secret. Nothing else in the system
    // would notice -- the kid differs, the artifact validates, and the old key was never
    // actually retired.
    const shared = secretFor("k");
    const result = run("verify", `old:${shared},new:${shared}`);
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/FAIL\s+new/);
    expect(result.stderr).toMatch(/Do not deploy this keyring/);
  });

  it("proves verification is running, not just returning true", () => {
    // The negative control. Without it every "ok" line could be passing because
    // verification is broken rather than because the keys are right.
    const result = run("verify", `solo:${secretFor("s")}`);
    expect(result.stdout).toMatch(/unknown key rejected \(negative control\)/);
  });

  it("rejects a key below the signing minimum", () => {
    const result = run("verify", "aa:tooshort");
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/at least 32 characters/);
  });

  it("rejects an --active kid that is not in the ring", () => {
    const result = run(
      "verify",
      `old:${secretFor("o")}`,
      "--active",
      "nonexistent",
    );
    expect(result.status).toBe(1);
  });

  it("needs a spec", () => {
    expect(run("verify").status).toBe(2);
    // A flag in the spec position is a misuse, not an empty ring.
    expect(run("verify", "--active", "new").status).toBe(2);
  });
});

describe("the tool itself", () => {
  it("exits 2 on an unknown command, so a typo does not read as success", () => {
    const result = run("rotate-everything-now");
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/usage/);
  });

  it("says plainly that it touches nothing", () => {
    // Rotation is deliberate. A tool that COULD perform it is a tool that can perform it
    // by accident, so this one is read-only and says so where someone will read it.
    expect(run("--help").stderr).toMatch(/never calls AWS/);
  });
});
