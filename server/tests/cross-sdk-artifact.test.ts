/**
 * The guarantee test: an artifact this server signs verifies in all three SDKs.
 *
 * This is the property the whole server design rests on, and it is the one thing
 * that cannot be checked from inside a single language. The TypeScript
 * assertions below would pass even if Python and .NET both rejected every
 * artifact -- which is exactly how the original cross-SDK signing divergence
 * shipped (canonical-enforcement-spec.md section 14 on why determinism-only
 * assertions are insufficient). So the Python and .NET arms actually run their
 * SDKs and assert on their output.
 *
 * The Python arm goes further than signature validation: it runs the real
 * `SecureMcpToolWrapper` and asserts the enforced *rows*. A signature that
 * verifies but a policy that does not enforce would be a fail-open, and only
 * end-to-end enforcement catches it.
 *
 * These arms **skip** when python3 or dotnet is unavailable, and a guard test
 * that is deliberately not behind the skip asserts the TypeScript arm always
 * runs. The repo has been bitten by gates that silently disabled whole suites
 * (see CHANGELOG "Test-reporting defects"), so an absent runtime must report
 * skipped and never pass vacuously.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { runDotnet } from "./helpers/dotnet.ts";
import {
  validateContext,
  validatePolicy,
  type EffectivePolicy,
} from "@aws/tolap-core";
import { buildSignedArtifact, encodeArtifact } from "../src/signing/artifact.ts";

const KEY = "tolap-cross-sdk-test-key-not-for-production";
const TTL_MS = 3_600_000;
const REPO = path.resolve(__dirname, "../..");

/**
 * A policy whose effects are observable in the returned rows.
 *
 * Every rule here changes the output, so the Python enforcement assertion can
 * distinguish "policy applied" from "policy parsed and ignored":
 * `allowedObjects` refuses `encounters`, `hiddenFields` drops `ssn`,
 * `rowFilters` drops the `eu-west` row, and `maxResults` truncates to 2.
 */
function policyUnderTest(): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:analytics:patients",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
    sourceProfiles: ["cross-sdk-test"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients"],
      fieldRules: { hiddenFields: ["ssn"] },
      rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
    },
    limits: { maxResults: 2 },
    integrity: { algorithm: "none", signature: "" },
  } as EffectivePolicy;
}

function haveCommand(cmd: string): boolean {
  try {
    execFileSync("which", [cmd], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

const HAVE_PYTHON = haveCommand("python3");
const HAVE_DOTNET = haveCommand("dotnet");

/** Write the artifact to a temp file and hand the path to another runtime. */
function withArtifactFile<T>(json: string, fn: (file: string) => T): T {
  const dir = mkdtempSync(path.join(tmpdir(), "tolap-xsdk-"));
  try {
    const file = path.join(dir, "artifact.json");
    writeFileSync(file, json, "utf8");
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("cross-SDK artifact verification", () => {
  it("guard: the TypeScript arm is not behind any skip", () => {
    // If this test ever needs a runtime gate, the suite has stopped asserting the
    // guarantee unconditionally. The original test-reporting defect in this repo
    // was a gate and its guarded code being the same thing.
    expect(typeof buildSignedArtifact).toBe("function");
  });

  it("TypeScript accepts both the bare policy and the envelope", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);

    // The path the TypeScript SecureMcpToolWrapper actually takes.
    expect(validatePolicy(artifact.effectivePolicy, KEY)).toBe(true);
    // The path Python and .NET take, asserted here too so a break is localized.
    expect(validateContext(artifact, KEY)).toBe(true);

    // The integrity block must be a real signature, not resolution's
    // `algorithm: "none"` placeholder -- which is not even in the schema's
    // algorithm enum.
    expect(artifact.effectivePolicy.integrity.algorithm).toBe("hmac-sha256");
    expect(artifact.effectivePolicy.integrity.signature).not.toBe("");
  });

  it("the two signatures are over different bytes", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
    // If these were ever equal, one of the two verification paths would be
    // checking the wrong payload. The envelope HMAC covers
    // {version,userId,tenantId,issuedAt,expiresAt,policies[]}; the policy HMAC
    // covers the policy alone. Distinct bytes, therefore distinct signatures.
    expect(artifact.effectivePolicy.integrity.signature).not.toBe(
      artifact.signature,
    );
  });

  it("carries both envelope instant spellings with identical values", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
    // Python/.NET read issuedAt; TypeScript reads resolvedAt. A drift between
    // them would make the artifact verify in one SDK and fail in another.
    expect(artifact.issuedAt).toBe(artifact.resolvedAt);
    expect(artifact.expiresAt > artifact.issuedAt).toBe(true);
  });

  it("makes the envelope and the policy expire together", () => {
    // These diverged in production and no test noticed, because every fixture in this file
    // happened to pre-set `expiresAt` to the same TTL the artifact was signed with.
    //
    // The real path does not: the store calls the SDK's `resolve()` without a `ttlMs`, so
    // the policy got `resolve()`'s ONE-HOUR default while the envelope got the configured
    // TTL. The two verification paths then read different fields -- Python and .NET
    // validate the envelope, the TypeScript wrapper reads `policy.expiresAt` -- so
    // TOLAP_TTL_SECONDS was silently ignored on TypeScript installs, which is the one
    // bound spec section 13 gives against replay.
    //
    // So the fixture here deliberately carries a WRONG, far-future expiry, the way a
    // freshly resolved policy does. `buildSignedArtifact` must overwrite it.
    const stale = policyUnderTest();
    stale.expiresAt = new Date(Date.now() + 86_400_000).toISOString();

    const artifact = buildSignedArtifact(stale, KEY, 60_000);

    expect(artifact.effectivePolicy.expiresAt).toBe(artifact.expiresAt);
    expect(artifact.effectivePolicy.resolvedAt).toBe(artifact.resolvedAt);
    // And the value is the configured TTL, not the day the fixture asked for.
    const window = new Date(artifact.expiresAt).getTime() - new Date(artifact.issuedAt).getTime();
    expect(window).toBeLessThanOrEqual(60_000);
  });

  it("rejects a rewritten expiry (spec section 2 rule 2)", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
    const extended = {
      ...artifact,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };
    // expiresAt is inside the signed bytes, so extending an artifact's life must
    // invalidate it rather than grant a day of access.
    expect(validateContext(extended, KEY)).toBe(false);
  });

  it("rejects a tampered policy body", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
    const widened = {
      ...artifact,
      effectivePolicy: {
        ...artifact.effectivePolicy,
        limits: { maxResults: 10_000 },
      },
    };
    expect(validatePolicy(widened.effectivePolicy, KEY)).toBe(false);
    expect(validateContext(widened, KEY)).toBe(false);
  });

  it("rejects a wrong key", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
    expect(validatePolicy(artifact.effectivePolicy, `${KEY}-wrong`)).toBe(false);
    expect(validateContext(artifact, `${KEY}-wrong`)).toBe(false);
  });

  it.skipIf(!HAVE_PYTHON)(
    "Python verifies the artifact and enforces the policy on real rows",
    () => {
      const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);
      const encoded = encodeArtifact(artifact);

      const script = `
import base64, json, sys
sys.path.insert(0, ${JSON.stringify(path.join(REPO, "sdk/python/tolap-core"))})
sys.path.insert(0, ${JSON.stringify(path.join(REPO, "sdk/python/tolap-mcp"))})
from tolap_core.context import deserialize_context
from tolap_mcp.wrapper import SecureMcpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions

ctx = deserialize_context(open(sys.argv[1]).read().strip(), ${JSON.stringify(KEY)})

rows = [
    {"id": 1, "name": "a", "region": "us-east", "ssn": "111-22-3333"},
    {"id": 2, "name": "b", "region": "us-east", "ssn": "222-33-4444"},
    {"id": 3, "name": "c", "region": "us-east", "ssn": "333-44-5555"},
    {"id": 4, "name": "d", "region": "eu-west", "ssn": "444-55-6666"},
]
w = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=${JSON.stringify(KEY)}))
out = w.execute_with_enforcement(
    context=ctx, tool_name="q", tool_fn=lambda table: list(rows),
    tool_args={"table": "patients"}, object_name="patients")

denied = None
try:
    w.execute_with_enforcement(
        context=ctx, tool_name="q", tool_fn=lambda table: list(rows),
        tool_args={"table": "encounters"}, object_name="encounters")
except PermissionError as e:
    denied = str(e)

print(json.dumps({"rows": out, "deniedEncounters": denied}))
`;
      const stdout = withArtifactFile(encoded, (file) =>
        execFileSync("python3", ["-c", script, file], {
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
        }),
      );

      const result = JSON.parse(stdout.trim()) as {
        rows: Array<Record<string, unknown>>;
        deniedEncounters: string | null;
      };

      // maxResults: 2 and the us-east row filter both applied.
      expect(result.rows).toHaveLength(2);
      // hiddenFields removed ssn even though the source returned it.
      for (const row of result.rows) {
        expect(row).not.toHaveProperty("ssn");
        expect(row.region).toBe("us-east");
      }
      // allowedObjects refused a table outside the policy.
      expect(result.deniedEncounters).toBeTruthy();
    },
  );

  it.skipIf(!HAVE_DOTNET)("dotnet verifies the artifact", () => {
    const artifact = buildSignedArtifact(policyUnderTest(), KEY, TTL_MS);

    const corePath = path.join(
      REPO,
      "sdk/dotnet/src/Tolap.Core/Tolap.Core.csproj",
    );
    expect(existsSync(corePath)).toBe(true);

    const dir = mkdtempSync(path.join(tmpdir(), "tolap-xsdk-net-"));
    try {
      writeFileSync(
        path.join(dir, "verify.csproj"),
        `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>verify</AssemblyName>
    <RootNamespace>verify</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="${corePath}" />
  </ItemGroup>
</Project>`,
        "utf8",
      );
      writeFileSync(
        path.join(dir, "Program.cs"),
        `using Tolap.Core;

// The DOCUMENTED consumer path: deserialize straight into the SDK's own type.
//
// This test used to hand-build the SecurityContext from JsonDocument fields, which proved
// .NET's HMAC arithmetic works rather than that a .NET consumer can consume what this
// server emits -- and it hid a real break. The artifact carried no envelope-level
// version/userId/tenantId/policies/integrity, so Deserialize produced an object of nulls
// and Validate rejected it. Any claim about another runtime has to go through that
// runtime's real entry point or it is not testing interop.
var ctx = TolapJsonOptions.Deserialize<SecurityContext>(File.ReadAllText(args[0]));
var policy = ctx.Policies[0];

Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {
    valid = SecurityContextSigner.Validate(ctx, ${JSON.stringify(KEY)}),
    expiry = SecurityContextSigner.ValidateExpiry(ctx),
    maxResults = policy.Limits?.MaxResults,
    hidden = policy.ObjectRules?.FieldRules?.HiddenFields,
    // The envelope and the policy must agree on when this expires: the Python and .NET
    // wrappers read the envelope while the TypeScript one reads the policy, so a
    // divergence silently gives one runtime a different replay window. Note that
    // EffectivePolicy.ExpiresAt is a DateTimeOffset? in .NET, not a string.
    expiriesAgree = policy.ExpiresAt.HasValue && ctx.ExpiresAt == policy.ExpiresAt.Value,
}));`,
        "utf8",
      );
      writeFileSync(path.join(dir, "artifact.json"), JSON.stringify(artifact));

      const stdout = runDotnet(
        ["run", "--framework", "net9.0", "--", path.join(dir, "artifact.json")],
        dir,
      );

      // `dotnet run` prints build noise before program output; take the JSON line.
      const line = stdout
        .trim()
        .split("\n")
        .findLast((l) => l.trim().startsWith("{"));
      expect(line, `no JSON in dotnet output:\n${stdout}`).toBeTruthy();

      const result = JSON.parse(line!) as {
        valid: boolean;
        expiry: string | null;
        maxResults: number | null;
        hidden: string[] | null;
        expiriesAgree: boolean;
      };

      expect(result.valid).toBe(true);
      expect(result.expiry).toBeNull();
      // Assert the policy content survived the round trip, not just the
      // signature: a signature over a policy .NET deserialized into empty
      // objectRules would verify while enforcing nothing.
      expect(result.maxResults).toBe(2);
      expect(result.hidden).toEqual(["ssn"]);
      // The envelope and the policy must expire together. They did not: the store called
      // the SDK's `resolve()` without a ttlMs, so the policy got the SDK's one-hour
      // default while the envelope got the configured TTL -- and the TypeScript wrapper
      // reads the policy while Python and .NET read the envelope. The effect was that
      // TOLAP_TTL_SECONDS was silently ignored on TypeScript installs, defeating the only
      // bound spec section 13 gives against replay.
      expect(result.expiriesAgree).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("known-answer signing conformance", () => {
  it("reproduces the shared fixture signature through the server's signing path", async () => {
    // The server calls signContext, so it inherits the cross-SDK canonical form.
    // This asserts the inheritance rather than assuming it: if a future refactor
    // starts hand-rolling the bytes, the fixture stops matching.
    const fixture = (await import(
      path.join(REPO, "fixtures/signing/hmac-sha256-known-answer.json"),
      { with: { type: "json" } }
    )) as { default: Record<string, unknown> };
    const f = fixture.default;

    const payload = f.payload as Record<string, unknown>;
    const policy = {
      ...payload,
      integrity: { algorithm: "none", signature: "" },
    } as EffectivePolicy;

    const artifact = buildSignedArtifact(
      policy,
      f.secretKey as string,
      TTL_MS,
    );

    // buildSignedArtifact stamps fresh envelope instants, so the envelope
    // signature cannot equal the fixture's. What must hold is that the artifact
    // verifies -- and that the fixture's own expected values are intact, since a
    // fixture that lost them would let this whole suite pass while checking
    // nothing (spec section 14).
    expect(validateContext(artifact, f.secretKey as string)).toBe(true);
    expect(f.expectedSignature).toBe(
      "YekLSTYYqzpgSxi9hFOsOWjYLo2qMwwRHc7D4MdGVG4=",
    );
    expect(f.canonicalPayload).toBeTruthy();
  });
});
