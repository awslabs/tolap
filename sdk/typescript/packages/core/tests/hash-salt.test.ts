/**
 * Salted `hash` masking (spec §6).
 *
 * The `hash` mask was an unsalted, truncated digest. That is fine as a
 * pseudonymous join key and *not* fine as confidentiality: the input spaces that
 * matter here are small enough to enumerate. There are ~10^9 SSNs and ~4x10^4
 * plausible dates of birth, so a masked column of either is recoverable with a
 * rainbow table in seconds, while the output still looks like an opaque token.
 *
 * An optional secret salt turns the digest into a keyed HMAC. The join-key
 * property survives — the same salt over the same value yields the same pseudonym
 * everywhere — but recovery now needs the salt, which is a deployment secret.
 *
 * The recovery test below is the point of this file: it demonstrates the actual
 * attack against the unsalted form and then shows the salt defeating it.
 * Asserting only "salted differs from unsalted" would pass against a broken
 * implementation that merely appended the salt to the output.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { applyFieldMasking, applyMaskingToTree } from "../src/enforcement.js";
import type { EffectivePolicy } from "../src/types.js";

const SALT = "deployment-secret-salt-from-kms";

function policy(algorithm?: string): EffectivePolicy {
  return {
    version: "1.0",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: [],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      fieldRules: {
        maskedFields: [
          {
            field: "ssn",
            maskType: "hash",
            ...(algorithm ? { parameters: { algorithm } } : {}),
          },
        ],
      },
    },
    integrity: { algorithm: "none", signature: "" },
  };
}

const sha256Of = (value: string) =>
  createHash("sha256").update(value).digest("hex").slice(0, 16);

describe("§6: the salt defeats brute force", () => {
  it("shows an unsalted hash is recoverable by rainbow table", () => {
    // The vulnerability, demonstrated rather than asserted abstractly.
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy())
      .ssn as string;

    // An attacker who knows the format enumerates candidates and matches the
    // digest. Only the last four digits are unknown here, which is a 10^4 search
    // — the full 10^9 SSN space is minutes of CPU.
    let recovered: string | undefined;
    for (let candidate = 6780; candidate < 6800; candidate++) {
      const guess = `123-45-${candidate}`;
      if (sha256Of(guess) === masked) {
        recovered = guess;
        break;
      }
    }

    expect(recovered).toBe("123-45-6789");
  });

  it("resists the same attack when salted", () => {
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT)
      .ssn as string;

    for (let candidate = 6780; candidate < 6800; candidate++) {
      expect(sha256Of(`123-45-${candidate}`)).not.toBe(masked);
    }
    expect(masked).not.toBe("123-45-6789");
  });

  it("is neither the plaintext nor the plain digest", () => {
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT)
      .ssn as string;
    const unsalted = applyFieldMasking({ ssn: "123-45-6789" }, policy())
      .ssn as string;

    expect(masked).not.toBe("123-45-6789");
    expect(masked).not.toBe(unsalted);
    // Not merely the digest with the salt glued on, which would leak the digest.
    expect(masked).not.toContain(unsalted);
  });
});

describe("§6: the salt preserves the join-key property", () => {
  it("yields the same pseudonym for the same value and salt", () => {
    const first = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT);
    const second = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT);
    expect(first.ssn).toBe(second.ssn);
  });

  it("yields different pseudonyms for different values", () => {
    const first = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT);
    const second = applyFieldMasking({ ssn: "987-65-4321" }, policy(), SALT);
    expect(first.ssn).not.toBe(second.ssn);
  });

  it("yields different pseudonyms for different salts", () => {
    // Why the salt must match everywhere the pseudonym is joined.
    const first = applyFieldMasking({ ssn: "123-45-6789" }, policy(), "salt-a");
    const second = applyFieldMasking({ ssn: "123-45-6789" }, policy(), "salt-b");
    expect(first.ssn).not.toBe(second.ssn);
  });

  it("keeps the 16 hex char shape", () => {
    // The wire contract does not change, so a fixed-width column still fits.
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy(), SALT);
    expect(masked.ssn).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("§6: backward compatibility", () => {
  it("preserves the existing digest with no salt", () => {
    // Existing join keys must not change for integrators who do not opt in.
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy());
    expect(masked.ssn).toBe(sha256Of("123-45-6789"));
  });

  it.each([undefined, ""])("treats %j as unsalted", (empty) => {
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy(), empty);
    expect(masked.ssn).toBe(sha256Of("123-45-6789"));
  });
});

describe("§6: the salt across algorithms", () => {
  it.each(["sha256", "sha512", "blake2b"])(
    "%s honours the salt",
    (algorithm) => {
      const salted = applyFieldMasking(
        { ssn: "123-45-6789" },
        policy(algorithm),
        SALT,
      ).ssn as string;
      const unsalted = applyFieldMasking({ ssn: "123-45-6789" }, policy(algorithm))
        .ssn as string;

      expect(salted).not.toBe(unsalted);
      expect(salted).toMatch(/^[0-9a-f]{16}$/);
    },
  );

  it.each(["sha512", "blake2b"])(
    "salted %s does not collapse onto salted sha256",
    (algorithm) => {
      const salted = applyFieldMasking(
        { ssn: "123-45-6789" },
        policy(algorithm),
        SALT,
      ).ssn;
      const baseline = applyFieldMasking(
        { ssn: "123-45-6789" },
        policy("sha256"),
        SALT,
      ).ssn;
      expect(salted).not.toBe(baseline);
    },
  );

  it("still fails closed on an unsupported algorithm when salted", () => {
    // Salting must not turn a redact-on-unknown-algorithm into a disclosure.
    const masked = applyFieldMasking({ ssn: "123-45-6789" }, policy("md5"), SALT);
    expect(masked.ssn).toBe("[REDACTED]");
  });
});

describe("§6: the salt reaches nested shapes", () => {
  it("salts nested records", () => {
    const body = { results: [{ patient: { ssn: "123-45-6789" } }] };

    const masked = applyMaskingToTree(body, policy(), SALT);
    const unsalted = applyMaskingToTree(body, policy());

    const got = masked.results[0].patient.ssn;
    expect(got).not.toBe("123-45-6789");
    expect(got).not.toBe(unsalted.results[0].patient.ssn);
  });

  it("accepts a Buffer salt", () => {
    // A salt fetched from a KMS arrives as bytes as often as a string.
    const asString = applyFieldMasking({ ssn: "1" }, policy(), "abc");
    const asBuffer = applyFieldMasking({ ssn: "1" }, policy(), Buffer.from("abc"));
    expect(asString.ssn).toBe(asBuffer.ssn);
  });
});
