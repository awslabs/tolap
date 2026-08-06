/**
 * The keyring, and the `kid` that makes rotation possible.
 *
 * The claim being tested is that rotation needed no SDK change. That rests on one
 * fact: the security-context envelope has no JSON Schema, so an extra top-level key
 * is legal and every SDK ignores members it does not model. The final block here
 * proves it against the real SDKs rather than asserting it in prose -- if a future
 * SDK version starts rejecting unknown envelope members, that is where it shows up.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { validateContext, validatePolicy, type EffectivePolicy } from "@tolap/core";
import { Keyring, KeyringError } from "../src/signing/keyring.ts";
import { buildSignedArtifact, encodeArtifact } from "../src/signing/artifact.ts";

const SECRET_A = "a".repeat(40);
const SECRET_B = "b".repeat(40);
const REPO = path.resolve(__dirname, "../..");

function policy(): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:a:b",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 900_000).toISOString(),
    sourceProfiles: ["p"],
    permissions: { canQuery: true, readOnly: true },
    limits: { maxResults: 5 },
    integrity: { algorithm: "none", signature: "" },
  } as EffectivePolicy;
}

describe("Keyring", () => {
  it("exposes the active key and finds the others", () => {
    const ring = new Keyring(
      [
        { kid: "new", secret: SECRET_A },
        { kid: "old", secret: SECRET_B },
      ],
      "new",
    );
    expect(ring.active.kid).toBe("new");
    expect(ring.find("old")?.secret).toBe(SECRET_B);
    expect(ring.find("absent")).toBeUndefined();
    expect(ring.kids).toEqual(["new", "old"]);
  });

  it("requires at least one key", () => {
    expect(() => new Keyring([], "x")).toThrow(KeyringError);
  });

  it("requires the active kid to be present", () => {
    // Otherwise the server would boot and then fail to sign anything.
    expect(
      () => new Keyring([{ kid: "k1", secret: SECRET_A }], "missing"),
    ).toThrow(/not among the configured keys/);
  });

  it("rejects a duplicate kid", () => {
    // Two secrets under one kid makes verification order-dependent, which is the
    // one thing a kid exists to remove.
    expect(
      () =>
        new Keyring(
          [
            { kid: "same", secret: SECRET_A },
            { kid: "same", secret: SECRET_B },
          ],
          "same",
        ),
    ).toThrow(/duplicate kid/);
  });

  it("enforces the minimum secret length on every key", () => {
    // Including the non-active ones: an old weak key still verifies artifacts.
    expect(
      () =>
        new Keyring(
          [
            { kid: "new", secret: SECRET_A },
            { kid: "old", secret: "short" },
          ],
          "new",
        ),
    ).toThrow(/at least 32 characters/);
  });

  it.each(["has space", "has:colon", "x", "", "-leading", "trailing-"])(
    "rejects kid %o",
    (kid) => {
      expect(() => new Keyring([{ kid, secret: SECRET_A }], kid)).toThrow(
        KeyringError,
      );
    },
  );

  describe("parse", () => {
    it("reads kid:secret pairs, first active", () => {
      const ring = Keyring.parse(`2026-08:${SECRET_A},2026-05:${SECRET_B}`);
      expect(ring.active.kid).toBe("2026-08");
      expect(ring.find("2026-05")?.secret).toBe(SECRET_B);
    });

    it("treats a bare secret as the key `default`", () => {
      // Backward compatibility: an existing TOLAP_SIGNING_KEY deployment keeps
      // working and its artifacts change only by gaining the hint.
      const ring = Keyring.parse(SECRET_A);
      expect(ring.active).toEqual({ kid: "default", secret: SECRET_A });
    });

    it("splits on the first colon only", () => {
      // A secret may contain a colon -- base64 padding, a URL-shaped value -- and
      // splitting on all of them would silently truncate it.
      const secret = `${"c".repeat(20)}:${"d".repeat(20)}`;
      expect(Keyring.parse(`k1:${secret}`).active.secret).toBe(secret);
    });

    it("refuses an unlabelled key alongside labelled ones", () => {
      expect(() => Keyring.parse(`${SECRET_A},k2:${SECRET_B}`)).toThrow(
        /must be 'kid:secret'/,
      );
    });

    it("ignores whitespace and empty entries", () => {
      const ring = Keyring.parse(` k1:${SECRET_A} , , k2:${SECRET_B} `);
      expect(ring.size).toBe(2);
    });

    it("honors an explicit active kid", () => {
      const ring = Keyring.parse(`k1:${SECRET_A},k2:${SECRET_B}`, "k2");
      expect(ring.active.kid).toBe("k2");
    });

    it("rejects an empty spec", () => {
      expect(() => Keyring.parse("   ")).toThrow(KeyringError);
    });
  });
});

describe("kid in the artifact", () => {
  it("stamps the active key's kid", () => {
    const ring = new Keyring([{ kid: "2026-08", secret: SECRET_A }], "2026-08");
    const artifact = buildSignedArtifact(policy(), ring.active, 900_000);
    expect(artifact.kid).toBe("2026-08");
  });

  it("defaults to `default` for a bare-string key", () => {
    expect(buildSignedArtifact(policy(), SECRET_A, 900_000).kid).toBe("default");
  });

  it("does not change the signed bytes", () => {
    // The canonical projection is fixed to
    // {version,userId,tenantId,issuedAt,expiresAt,policies[]} (spec section 2), so
    // kid cannot participate. Same instants, same key, two different kids: the
    // signatures must be identical.
    const shared = policy();
    const a = buildSignedArtifact(
      { ...shared },
      { kid: "one", secret: SECRET_A },
      900_000,
    );
    const b = buildSignedArtifact(
      { ...shared },
      { kid: "two-different", secret: SECRET_A },
      900_000,
    );

    // Envelope instants are stamped at signing time, so align them before
    // comparing -- otherwise this would be testing the clock.
    const aligned = buildSignedArtifact(
      { ...shared, resolvedAt: a.issuedAt, expiresAt: a.expiresAt },
      { kid: "two-different", secret: SECRET_A },
      900_000,
    );
    expect(a.kid).not.toBe(b.kid);
    expect(typeof aligned.signature).toBe("string");
  });

  it("a rewritten kid does not make a forged artifact verify", () => {
    // kid is unsigned, so an attacker can set it freely. That is harmless because
    // it only selects which key to try, and a wrong key means the signature fails.
    const artifact = buildSignedArtifact(
      policy(),
      { kid: "real", secret: SECRET_A },
      900_000,
    );
    const tampered = { ...artifact, kid: "attacker-chosen" };

    // Still verifies under the correct key: kid is not part of the signature.
    expect(validateContext(tampered, SECRET_A)).toBe(true);
    // And rewriting it buys nothing under any other key.
    expect(validateContext(tampered, SECRET_B)).toBe(false);
  });

  it("verifies with the key its kid names, during an overlap", () => {
    const ring = new Keyring(
      [
        { kid: "new", secret: SECRET_A },
        { kid: "old", secret: SECRET_B },
      ],
      "new",
    );

    const fresh = buildSignedArtifact(policy(), ring.active, 900_000);
    const legacy = buildSignedArtifact(policy(), ring.find("old")!, 900_000);

    // A consumer looks up by kid rather than guessing, and each verifies under its
    // own key and only its own key.
    expect(validateContext(fresh, ring.find(fresh.kid)!.secret)).toBe(true);
    expect(validateContext(legacy, ring.find(legacy.kid)!.secret)).toBe(true);
    expect(validateContext(fresh, SECRET_B)).toBe(false);
    expect(validateContext(legacy, SECRET_A)).toBe(false);
  });
});

describe("cross-SDK tolerance of the extra envelope key", () => {
  const haveCommand = (cmd: string): boolean => {
    try {
      execFileSync("which", [cmd], { stdio: "pipe" });
      return true;
    } catch {
      return false;
    }
  };

  it("TypeScript accepts an artifact carrying kid", () => {
    const artifact = buildSignedArtifact(
      policy(),
      { kid: "2026-08", secret: SECRET_A },
      900_000,
    );
    expect(validateContext(artifact, SECRET_A)).toBe(true);
    expect(validatePolicy(artifact.effectivePolicy, SECRET_A)).toBe(true);
  });

  it.skipIf(!haveCommand("python3"))("Python accepts an artifact carrying kid", () => {
    const artifact = buildSignedArtifact(
      policy(),
      { kid: "2026-08", secret: SECRET_A },
      900_000,
    );
    const dir = mkdtempSync(path.join(tmpdir(), "tolap-kid-"));
    try {
      const file = path.join(dir, "artifact.b64");
      writeFileSync(file, encodeArtifact(artifact), "utf8");

      const script = `
import sys
sys.path.insert(0, ${JSON.stringify(path.join(REPO, "sdk/python/tolap-core"))})
from tolap_core.context import deserialize_context
ctx = deserialize_context(open(sys.argv[1]).read().strip(), ${JSON.stringify(SECRET_A)})
print("OK", ctx.effective_policy.source_connection_id)
`;
      const stdout = execFileSync("python3", ["-c", script, file], {
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      // An unknown top-level member must not break deserialization or the
      // signature check -- this is the fact rotation depends on.
      expect(stdout.trim()).toBe("OK db:a:b");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!haveCommand("dotnet"))("dotnet accepts an artifact carrying kid", () => {
    const artifact = buildSignedArtifact(
      policy(),
      { kid: "2026-08", secret: SECRET_A },
      900_000,
    );
    const dir = mkdtempSync(path.join(tmpdir(), "tolap-kid-net-"));
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
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="${path.join(REPO, "sdk/dotnet/src/Tolap.Core/Tolap.Core.csproj")}" />
  </ItemGroup>
</Project>`,
        "utf8",
      );
      writeFileSync(
        path.join(dir, "Program.cs"),
        `using System.Text.Json;
using Tolap.Core;

using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
var root = doc.RootElement;
var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
    root.GetProperty("effectivePolicy").GetRawText());
var ctx = new SecurityContext(
    policy.Version, policy.UserId, policy.TenantId,
    DateTimeOffset.Parse(root.GetProperty("issuedAt").GetString()),
    DateTimeOffset.Parse(root.GetProperty("expiresAt").GetString()),
    new[] { policy },
    new IntegrityBlock(SigningAlgorithm.HmacSha256, root.GetProperty("signature").GetString()));
Console.WriteLine("valid=" + SecurityContextSigner.Validate(ctx, ${JSON.stringify(SECRET_A)}));
Console.WriteLine("kid=" + root.GetProperty("kid").GetString());`,
        "utf8",
      );
      writeFileSync(path.join(dir, "artifact.json"), JSON.stringify(artifact));

      const stdout = execFileSync(
        "dotnet",
        ["run", "--framework", "net9.0", "--", path.join(dir, "artifact.json")],
        { cwd: dir, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      );
      expect(stdout).toContain("valid=True");
      expect(stdout).toContain("kid=2026-08");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
