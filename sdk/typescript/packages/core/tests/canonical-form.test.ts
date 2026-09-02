/**
 * The two canonical-form rules a cross-SDK parity audit found all three SDKs getting wrong
 * (spec §1, §2 rule 4, §14).
 *
 * Neither is observable through an access decision: both produce identical enforcement and
 * differ only in the *signed bytes*. So no test comparing what a policy permits could have
 * caught either, and the only thing that did was comparing bytes across the three languages —
 * which is exactly what §14 recommends, and why.
 *
 * Driven from `fixtures/canonical-form/number-and-timestamp-forms.json` so all three SDKs are
 * held to one table.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { normalizeTimestamp } from "../src/context.js";

interface Rule {
  rule: string;
  cases: Array<{ input: unknown; canonical: string }>;
  timezones?: string[];
}

const fixture = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../../../../fixtures/canonical-form/number-and-timestamp-forms.json"),
    "utf-8",
  ),
) as { rules: Rule[] };

const rule = (name: string): Rule => {
  const found = fixture.rules.find((r) => r.rule === name);
  if (!found) throw new Error(`fixture is missing rule '${name}'`);
  return found;
};

describe("whole-number floats render as integers", () => {
  // TypeScript was already correct here; Python emitted `1.0`. Asserted anyway, because "the
  // one that was right" is exactly where a later refactor reintroduces the divergence unnoticed.
  for (const { input, canonical } of rule("whole-number-floats-render-as-integers").cases) {
    it(`renders ${JSON.stringify(input)} as ${canonical}`, () => {
      expect(JSON.stringify(input)).toBe(canonical);
    });
  }

  it("keeps booleans as booleans", () => {
    // The trap in the fix rather than in the bug. Python's `bool` is a subclass of `int`, so a
    // numeric coercion that shortens whole numbers can turn `true` into `1`. Trivially safe in
    // JavaScript and asserted so the shared table means the same thing in all three languages.
    expect(JSON.stringify(true)).toBe("true");
    expect(JSON.stringify(false)).toBe("false");
  });
});

describe("offset-less timestamps are UTC", () => {
  const timestamps = rule("offsetless-timestamps-are-utc");

  for (const { input, canonical } of timestamps.cases) {
    it(`normalizes ${String(input)} to ${canonical}`, () => {
      // This is the bug, and it was TypeScript's too: `new Date("2026-09-01T09:58:00")` is
      // parsed as LOCAL time by ECMAScript, so the same JSON signed to a different instant on
      // every host — a divergence between two deployments of one SDK, which no fixture pinned
      // to a single machine could detect.
      expect(normalizeTimestamp(String(input))).toBe(canonical);
    });
  }

  it("is independent of the host timezone", () => {
    // The property that actually matters, and why the fixture lists timezones. Node reads `TZ`
    // lazily per `Date` operation, so swapping it mid-process is a real change of host clock
    // for this purpose — closer than CI's UTC-only run can get on its own.
    const zones = timestamps.timezones ?? [];
    expect(zones.length).toBeGreaterThan(0);

    const original = process.env.TZ;
    try {
      for (const zone of zones) {
        process.env.TZ = zone;
        for (const { input, canonical } of timestamps.cases) {
          expect(normalizeTimestamp(String(input)), `TZ=${zone}`).toBe(canonical);
        }
      }
    } finally {
      if (original === undefined) delete process.env.TZ;
      else process.env.TZ = original;
    }
  });

  it("passes an unparseable value through verbatim", () => {
    // Deliberately not a throw here: §1 has the signature cover exactly what was transported,
    // and `validateExpiry` — which rejects an unparseable expiry — is the control that stops it.
    // Asserted so the UTC-assumption above cannot quietly start rewriting garbage into a date.
    expect(normalizeTimestamp("not-a-date")).toBe("not-a-date");
  });
});
