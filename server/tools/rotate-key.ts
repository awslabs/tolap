/**
 * Signing-key rotation helper.
 *
 * `docs/policy-server.md` documents the procedure and the procedure is correct. What it
 * cannot do is tell you whether the keyring you are about to deploy behaves the way you
 * think it does — and the failure mode is bad enough to be worth a tool.
 *
 * The dangerous step is not adding a key. It is **dropping the old one**, at step 4, after
 * the overlap window. Drop it too early and every artifact still in flight becomes
 * unverifiable: installs hold a signed policy whose key the server no longer knows, and
 * because enforcement fails closed the symptom is a broad denial appearing across services
 * that have nothing obviously in common. Nothing in the SDKs reports "unknown kid" as
 * distinct from "bad signature", so the error an operator sees does not point at the cause.
 *
 * So this does two things the runbook cannot:
 *
 *   generate   mint a key of the right length and print the two env vars, so a rotation
 *              does not begin with someone choosing a secret by hand
 *
 *   verify     take a keyring spec, sign an artifact under the active key, and prove that
 *              *every* key in the ring can still verify what it signed — plus prove that a
 *              key NOT in the ring cannot. That second half is the one that matters: a
 *              check which only ever passes is not a check.
 *
 * Read-only with respect to AWS. It never writes a secret, never calls Secrets Manager,
 * and never touches the running service. Rotation is a deliberate act; a tool that could
 * perform it is a tool that can perform it by accident.
 *
 *   node --experimental-strip-types tools/rotate-key.ts generate
 *   node --experimental-strip-types tools/rotate-key.ts generate --kid 2026-08
 *   node --experimental-strip-types tools/rotate-key.ts verify "old:AAA...,new:BBB..."
 *   node --experimental-strip-types tools/rotate-key.ts verify "..." --active new
 */

import { randomBytes } from "node:crypto";
import { validateContext, validatePolicy, type EffectivePolicy } from "@aws/tolap-core";
import { Keyring, type SigningKey } from "../src/signing/keyring.ts";
import { buildSignedArtifact } from "../src/signing/artifact.ts";
import { MIN_SIGNING_KEY_LENGTH } from "../src/config.ts";

/**
 * 32 bytes, which is 43 base64url characters — comfortably past the 32-character minimum
 * the config enforces, and a full HMAC-SHA256 block of entropy. Not a passphrase: a
 * human-chosen secret here is the weakest part of an otherwise sound signing scheme.
 */
const KEY_BYTES = 32;

/** A `kid` from the date, because rotations are dated events and `key2` tells you nothing. */
function defaultKid(now: Date): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

function generateSecret(): string {
  return randomBytes(KEY_BYTES).toString("base64url");
}

/** A policy with observable rules, so verification is exercising real bytes. */
function samplePolicy(now: Date): EffectivePolicy {
  return {
    version: "1.0",
    userId: "rotation-check",
    tenantId: "rotation-check",
    sourceConnectionId: "db:rotation:check",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 900_000).toISOString(),
    sourceProfiles: ["rotation-check"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients"],
      fieldRules: { hiddenFields: ["ssn"] },
    },
    limits: { maxResults: 2 },
    integrity: { algorithm: "none", signature: "" },
  } as EffectivePolicy;
}

function generate(args: string[]): number {
  const kidFlag = args.indexOf("--kid");
  const now = new Date();
  const kid = kidFlag === -1 ? defaultKid(now) : args[kidFlag + 1];

  if (kid === undefined || kid === "") {
    console.error("--kid needs a value");
    return 2;
  }
  // A colon would split wrong when the spec is parsed back: `kid:secret` pairs split on
  // the FIRST colon, so a kid containing one silently truncates.
  if (kid.includes(":") || kid.includes(",")) {
    console.error(`kid must not contain ':' or ',' — got ${JSON.stringify(kid)}`);
    return 2;
  }

  const secret = generateSecret();
  console.log(`# New signing key. ${secret.length} chars (minimum ${MIN_SIGNING_KEY_LENGTH}).`);
  console.log("#");
  console.log("# Step 1 of the rotation: add it alongside the CURRENT key, with the");
  console.log("# current one still ACTIVE. Both verify from this moment on, which is what");
  console.log("# removes the flag day.");
  console.log("#");
  console.log("# Then run `verify` against the combined spec BEFORE deploying it, and");
  console.log("# again before you drop the old key at step 4. Dropping it early makes");
  console.log("# every artifact still in flight unverifiable, and enforcement fails");
  console.log("# closed — so the symptom is a broad denial, not an obvious key error.");
  console.log("");
  console.log(`TOLAP_SIGNING_KEYS="<current-kid>:<current-secret>,${kid}:${secret}"`);
  console.log(`TOLAP_ACTIVE_KID=<current-kid>   # flip to ${kid} at step 3`);
  return 0;
}

function verify(args: string[]): number {
  const spec = args[0];
  if (spec === undefined || spec.startsWith("--")) {
    console.error('verify needs a keyring spec: verify "old:AAA,new:BBB" [--active new]');
    return 2;
  }
  const activeFlag = args.indexOf("--active");
  const activeKid = activeFlag === -1 ? undefined : args[activeFlag + 1];

  let keyring: Keyring;
  try {
    keyring = Keyring.parse(spec, activeKid);
  } catch (error) {
    console.error(`keyring rejected: ${(error as Error).message}`);
    return 1;
  }

  const now = new Date();
  const artifact = buildSignedArtifact(samplePolicy(now), keyring.active, 900_000);

  console.log(`keys      ${keyring.kids.join(", ")}`);
  console.log(`active    ${keyring.active.kid}`);
  console.log(`signed    kid=${artifact.kid}`);
  console.log("");

  if (artifact.kid !== keyring.active.kid) {
    console.error(
      `FAIL  artifact carries kid=${artifact.kid} but the active key is ${keyring.active.kid}`,
    );
    return 1;
  }

  let failures = 0;

  // Every key in the ring must verify what the active key signed. During an overlap this
  // is the property installs depend on: they may hold either key, and neither should be
  // able to reject a current artifact.
  for (const kid of keyring.kids) {
    const key = keyring.find(kid) as SigningKey;
    const envelopeOk = validateContext(artifact as never, key.secret);
    const policyOk = validatePolicy(artifact.effectivePolicy, key.secret);
    const expected = kid === keyring.active.kid;

    // Only the signing key should verify: HMAC means a different key produces a different
    // signature. A non-active key verifying would mean two entries share a secret, which
    // makes the rotation a no-op that looks complete.
    const ok = envelopeOk === expected && policyOk === expected;
    if (!ok) failures += 1;

    console.log(
      `${ok ? "ok  " : "FAIL"}  ${kid.padEnd(14)} envelope=${envelopeOk} policy=${policyOk}` +
        (expected ? "  (signing key: both must be true)" : "  (other key: both must be false)"),
    );
  }

  // The negative control. Without this the whole check could be passing because
  // verification is broken rather than because the keys are right.
  const stranger = generateSecret();
  const strangerEnvelope = validateContext(artifact as never, stranger);
  const strangerPolicy = validatePolicy(artifact.effectivePolicy, stranger);
  if (strangerEnvelope || strangerPolicy) {
    failures += 1;
    console.log(
      `FAIL  a key NOT in the ring verified this artifact — verification is not working`,
    );
  } else {
    console.log("ok    unknown key rejected (negative control)");
  }

  console.log("");
  if (failures > 0) {
    console.error(`${failures} check(s) failed. Do not deploy this keyring.`);
    return 1;
  }

  if (keyring.size === 1) {
    console.log(
      "Single key. Fine as a steady state, but an artifact signed under any OTHER key\n" +
        "cannot be verified — so this is only safe at step 4, after one full TTL has\n" +
        "elapsed since the active key became active.",
    );
  } else {
    console.log(
      `Overlap of ${keyring.size} keys, active ${keyring.active.kid}.\n` +
        "\n" +
        "Note what the overlap does and does not do. HMAC is symmetric, so ONLY the\n" +
        "signing key verifies a given artifact — an install holding just the old key\n" +
        "cannot verify one signed under the new key, which is what the FAIL/ok lines\n" +
        "above show. The overlap is on the SERVER side: it keeps the old key able to\n" +
        "sign (before the flip) and lets artifacts already issued under it stay\n" +
        "verifiable by installs that still hold it.\n" +
        "\n" +
        "That is why step 2 of the runbook is 'distribute BOTH keys to consumers' and\n" +
        "why it comes before step 3. An install must hold the new key before the active\n" +
        "kid flips, or its first post-flip artifact fails to verify — and enforcement\n" +
        "fails closed, so that is a denial rather than a warning.",
    );
  }
  return 0;
}

function usage(): number {
  console.error(
    [
      "usage:",
      "  rotate-key.ts generate [--kid 2026-08]",
      '  rotate-key.ts verify "old:AAA...,new:BBB..." [--active new]',
      "",
      "Read-only: never writes a secret, never calls AWS, never touches the service.",
    ].join("\n"),
  );
  return 2;
}

const [command, ...rest] = process.argv.slice(2);
const exitCode =
  command === "generate" ? generate(rest) : command === "verify" ? verify(rest) : usage();
process.exit(exitCode);
