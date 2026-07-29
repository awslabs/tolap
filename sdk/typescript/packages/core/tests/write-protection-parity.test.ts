/**
 * Cross-SDK parity for write protection (canonical spec §9).
 *
 * One policy, one method table, asserted with identical expected outcomes in all
 * three SDKs. The counterparts are:
 *
 *   - Python: `sdk/python/tests/test_write_protection_parity.py`
 *   - .NET: `tests/Tolap.Core.Tests/WriteProtectionParityTests.cs`
 *
 * The table is deliberately mixed so a single divergence in either control is
 * visible: the policy grants DELETE and POST while declaring itself read-only (so
 * the readOnly ceiling must override them), omits HEAD and OPTIONS from an
 * otherwise present allowedMethods (so the read methods are not implicitly
 * re-added), and spells one request method in lower case (so the comparison must be
 * case-insensitive).
 *
 * The two denial reasons are asserted, not just the boolean. They must stay
 * distinguishable across languages, because "method not allowed" is fixed by
 * widening allowedMethods and "method not allowed on a read-only policy" is fixed
 * by clearing readOnly -- an integrator who cannot tell them apart cannot tell
 * which policy edit will unblock them.
 *
 * Both controls previously failed OPEN in all three SDKs, and did so
 * *inconsistently* once partially fixed, which is the divergence class this file
 * guards.
 */

import { describe, expect, it } from "vitest";
import { validateEndpoint } from "../src/enforcement.js";
import type { EffectivePolicy } from "../src/types.js";

/** The shared parity policy. Identical field-for-field in all three SDKs. */
const PARITY_POLICY: EffectivePolicy = {
  version: "1.0",
  userId: "parity-user",
  tenantId: "parity-tenant",
  sourceConnectionId: "api:internal:parity",
  resolvedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  sourceProfiles: ["write-protection-parity"],
  permissions: { canQuery: true, canExport: false, readOnly: true },
  objectRules: {
    endpointRules: {
      allowedEndpoints: ["/api/*"],
      hiddenEndpoints: ["/api/admin/*"],
      allowedMethods: ["GET", "POST", "DELETE"],
    },
  },
  integrity: { algorithm: "none", signature: "" },
};

/** [path, method, allowed, reason] -- the canonical table. */
const PARITY_TABLE: Array<[string, string, boolean, string | undefined]> = [
  ["/api/x", "GET", true, undefined],
  ["/api/x", "get", true, undefined],
  ["/api/x", "HEAD", false, "method not allowed"],
  ["/api/x", "OPTIONS", false, "method not allowed"],
  ["/api/x", "POST", false, "method not allowed on a read-only policy"],
  ["/api/x", "delete", false, "method not allowed on a read-only policy"],
  ["/api/x", "PUT", false, "method not allowed"],
  ["/api/admin/y", "GET", false, "endpoint is hidden"],
  ["/other/z", "GET", false, "endpoint not in allowed set"],
];

describe("write protection: cross-SDK parity table", () => {
  for (const [path, method, allowed, reason] of PARITY_TABLE) {
    it(`${method} ${path} -> ${allowed ? "allowed" : reason}`, () => {
      const result = validateEndpoint(path, method, PARITY_POLICY);

      expect(result.allowed).toBe(allowed);
      expect(result.reason).toBe(reason);
    });
  }
});
