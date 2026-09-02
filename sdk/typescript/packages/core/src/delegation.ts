/**
 * TOLAP Delegation Chain Validation (canonical spec §15.3)
 *
 * A chain records how authority reached the principal making a call: a human
 * delegates to an agent, which delegates to a sub-agent. The invariant is that each
 * hop may hold **less** authority than its parent and never more. Without it, a
 * sub-agent could declare any purpose it liked and the chain would be decoration.
 *
 * The chain is only worth validating because it is inside the signed bytes — see
 * `SecurityContext.delegationChain`. Validating an unsigned chain would be checking
 * the attacker's own arithmetic.
 *
 * This validates the chain's *internal consistency*. It cannot establish that the
 * first hop's purpose was honestly declared; that is the stated limitation in
 * spec §13.
 */

import { globToRegex } from "./resolution.js";
import type { AccessResult, DelegationHop } from "./types.js";

// ---------------------------------------------------------------------------
// Purpose-glob matching -- a THIRD dialect, deliberately
// ---------------------------------------------------------------------------
//
// `resolution.ts` documents at length why the enforcement dialect (`globMatch`,
// `*` -> `.*`, case-insensitive) and the source-pattern dialect
// (`sourcePatternMatch`, `*` -> `[^:]*`, case-insensitive) must not be unified. This
// is the same argument for a third case, and neither existing helper can be called
// as-is:
//
// - Both are **case-insensitive**. Purpose comparison is case-SENSITIVE everywhere
//   else in this feature (`purposeId` at resolution, `judge.model` at the gate), and
//   a case-insensitive test here would admit a child purpose `Campaign-X` under a
//   parent `campaign-x` while resolution refused the same string. One rule saying
//   yes and the other no about the same value is the divergence class the canonical
//   spec exists to prevent.
// - `sourcePatternMatch`'s `*` stops at `:`. Purpose identifiers are hyphen-
//   delimited (`campaign-x-overlap`), so a parent `campaign-*` must reach a child
//   `campaign-x-overlap`; `[^:]*` happens to do that today only because purposes
//   contain no colons, which is a coincidence rather than a rule.
//
// So the *dialect* is the enforcement one -- `*` crosses everything -- and only the
// case sensitivity differs. That single difference is expressed by recompiling
// `globToRegex`'s source without its `i` flag, rather than by hand-rolling a fourth
// translation, and the reason is ReDoS: a naive `*` -> `[\s\S]*` translation
// backtracks catastrophically (measured: `("*a" x 40) + "-x"` against 200 `a`s does
// not return inside a minute, and JavaScript's RegExp has no evaluation timeout to cut
// it short, which is where .NET's match timeout does the work instead). `globToRegex`
// already emits the atomic-group shape that makes each wildcard commit; borrowing its
// source inherits that guarantee instead of reproducing the bug beside it.

/**
 * Bound on the pattern and value lengths one purpose glob may span.
 *
 * A second ceiling on total work, on top of the atomic-group shape above: spec §13
 * records that Python and TypeScript bound pattern and input length where .NET applies
 * a regex timeout. Fail-closed, so an over-long value denies the hop.
 *
 * The schema caps a purpose identifier at 128 characters, so this is generous by an
 * order of magnitude and cannot refuse a legitimate value.
 */
const MAX_PURPOSE_LENGTH = 1024;

/**
 * Glob matching for purpose identifiers: `*` matches any run of characters, crossing
 * every separator, and the comparison is **case-sensitive**.
 *
 * `?` is inherited from the enforcement dialect as a single-character wildcard. That
 * is a consequence of reusing the hardened compiler rather than a designed feature,
 * and it is unobservable in practice: `security-context.schema.json` constrains a hop
 * purpose to `^[a-z0-9*][a-z0-9*-]*$`, so `?` cannot appear in a schema-valid one.
 *
 * There is deliberately no `try`/`catch` around the recompilation — `globToRegex`
 * escapes every metacharacter it does not expand, so its source is always a
 * well-formed pattern, and a catch for it would be unreachable. Unreachable defensive
 * code is worse than none: it reads as a handled case that no test can exercise.
 */
function purposeGlobMatch(pattern: string, value: string): boolean {
  if (pattern.length > MAX_PURPOSE_LENGTH || value.length > MAX_PURPOSE_LENGTH) {
    return false;
  }

  // `.source` and no flags: same pattern, case-sensitive. Reading the flag off and
  // filtering it would be the same thing said less directly, since `i` is the only
  // flag `globToRegex` sets.
  return new RegExp(globToRegex(pattern).source).test(value);
}

/**
 * Whether a child purpose sits within a parent's scope.
 *
 * Three ways in, and the third is the one that matters:
 *
 * 1. Exactly equal. Delegation without narrowing.
 * 2. The parent is a glob that matches the child, so `campaign-*` admits
 *    `campaign-x-overlap`. This is how a parent expresses "any purpose in this
 *    family".
 * 3. The child extends the parent on a `-` **segment boundary**, so `campaign-x`
 *    admits `campaign-x-overlap` but **not** `campaign-xyz-evil`.
 *
 * The third rule exists because a plain prefix test — the obvious implementation —
 * accepts `campaign-xyz-evil` under `campaign-x`. The two purposes are unrelated;
 * one merely starts with the other's characters. Requiring the boundary makes the
 * prefix mean what a reader assumes it means.
 */
function isWithinScope(childPurpose: string, parentPurpose: string): boolean {
  if (childPurpose === parentPurpose) return true;

  if (parentPurpose.includes("*")) {
    return purposeGlobMatch(parentPurpose, childPurpose);
  }

  return childPurpose.startsWith(`${parentPurpose}-`);
}

/**
 * Whether every element of `child` appears in `parent`, compared case-sensitively.
 *
 * A subset test rather than equality: a hop may hold fewer scopes than its parent.
 */
function isSubset(child: string[], parent: string[]): boolean {
  const available = new Set(parent);
  return child.every((scope) => available.has(scope));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a delegation chain.
 *
 * @param chain
 * The hops, oldest first. `undefined`, empty, and single-hop chains are allowed:
 * there is no parent to widen against, so there is nothing to check. An absent
 * chain is not treated as suspicious because delegation is opt-in — every
 * pre-purpose context has none.
 *
 * @returns
 * An allow, or a denial naming the offending hop by index. The reason strings are
 * part of the contract; integrators log and branch on them.
 */
export function validateDelegationChain(
  chain: DelegationHop[] | undefined,
): AccessResult {
  if (chain === undefined || chain.length <= 1) return { allowed: true };

  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i];
    const child = chain[i + 1];

    // Either side absent adds no constraint. A hop that declares no purpose is not
    // claiming one, so there is nothing to narrow and nothing to exceed; the
    // purpose-scoped policy check at resolution is what refuses an undeclared
    // purpose, and doing it twice here would deny every legitimate partial chain.
    const parentPurpose = parent.declaredPurpose;
    const childPurpose = child.declaredPurpose;
    if (
      parentPurpose !== undefined &&
      parentPurpose !== "" &&
      childPurpose !== undefined &&
      childPurpose !== "" &&
      !isWithinScope(childPurpose, parentPurpose)
    ) {
      return {
        allowed: false,
        reason:
          `delegation hop ${i + 1} purpose '${childPurpose}' is not within ` +
          `parent scope '${parentPurpose}'`,
      };
    }

    // Subset, not equality: a hop may hold fewer scopes than its parent. An empty
    // parent set is therefore not "unrestricted" but "nothing left to pass on", so
    // any child scope exceeds it (spec §3). Absent on either side adds no
    // constraint, matching the purpose rule above -- so the test is against
    // `undefined`, never for emptiness.
    if (
      parent.scopeNarrowing !== undefined &&
      child.scopeNarrowing !== undefined &&
      !isSubset(child.scopeNarrowing, parent.scopeNarrowing)
    ) {
      return {
        allowed: false,
        reason: `delegation hop ${i + 1} scopes exceed parent delegation`,
      };
    }
  }

  return { allowed: true };
}
