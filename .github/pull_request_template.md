<!-- Thanks for contributing to TOLAP. -->

## What this changes

<!-- A short description of the change and why it is needed. -->

## Cross-SDK parity

TOLAP's guarantee is that one policy behaves identically in .NET, Python, and
TypeScript. A behavior change in one SDK without the others is a security defect,
not an inconsistency — so please confirm:

- [ ] Behavior changes are implemented in **all three** SDKs, or the change is
      genuinely language-specific (explain below).
- [ ] Shared fixtures in `fixtures/` were updated if behavior changed, and all
      three suites validate against them.
- [ ] If signing/canonicalization changed, the known-answer fixtures in
      `fixtures/signing/` were regenerated and all three SDKs produce the same
      bytes. See [`docs/canonical-enforcement-spec.md`](../docs/canonical-enforcement-spec.md).

## Security-relevant changes

If this touches signing, merging, identity extraction, or the enforcement
pipeline, describe which security properties it affects and how you verified
them. Enforcement changes should state whether the new behavior fails **open or
closed** when inputs are missing, malformed, or an unexpected shape.

## Testing

- [ ] All three test suites pass locally.
- [ ] New/changed behavior has a regression test that **fails before** the change
      and passes after.
- [ ] No existing test was weakened to make this pass. (If a test encoded
      behavior the spec forbids, say so explicitly.)
