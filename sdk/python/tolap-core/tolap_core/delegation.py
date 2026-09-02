"""Delegation-chain narrowing (canonical-enforcement-spec.md section 15.3).

A chain records how authority reached the principal making a call: a human delegates
to an agent, which delegates to a sub-agent. The invariant is that each hop may hold
less authority than its parent and never more. Without it, a sub-agent could declare
any purpose it liked and the chain would be decoration.

The chain is only worth validating because it is inside the signed bytes -- see
:attr:`tolap_core.models.SecurityContext.delegation_chain`. Validating an unsigned
chain would check the attacker's own arithmetic.

This validates the chain's *internal consistency*. It cannot establish that the first
hop's purpose was honestly declared; that is the stated limitation in spec section 13.
"""

from __future__ import annotations

from tolap_core.enforcement import AccessResult
from tolap_core.models import DelegationHop


def validate_delegation_chain(chain: list[DelegationHop] | None) -> AccessResult:
    """Validate a delegation chain, oldest hop first.

    ``None``, empty, and single-hop chains are allowed: there is no parent to widen
    against, so there is nothing to check. An absent chain is not treated as
    suspicious because delegation is opt-in -- every pre-purpose context has none.

    Returns an allow, or a denial naming the offending hop by index. The reason
    strings are part of the contract; integrators log and branch on them.
    """
    if chain is None or len(chain) <= 1:
        return AccessResult(allowed=True)

    for index in range(len(chain) - 1):
        parent = chain[index]
        child = chain[index + 1]

        # Either side absent adds no constraint. A hop that declares no purpose is
        # not claiming one, so there is nothing to narrow and nothing to exceed; the
        # purpose-scoped policy check at resolution is what refuses an undeclared
        # purpose, and doing it twice here would deny every legitimate partial chain.
        # An empty string is treated as absent, matching how the signing projection
        # normalizes it.
        if (
            parent.declared_purpose
            and child.declared_purpose
            and not _is_within_scope(child.declared_purpose, parent.declared_purpose)
        ):
            return AccessResult(
                allowed=False,
                reason=(
                    f"delegation hop {index + 1} purpose '{child.declared_purpose}' "
                    f"is not within parent scope '{parent.declared_purpose}'"
                ),
            )

        # Subset, not equality: a hop may hold fewer scopes than its parent. An empty
        # parent set is therefore not "unrestricted" but "nothing left to pass on", so
        # any child scope exceeds it (spec section 3). Absent on either side adds no
        # constraint, matching the purpose rule above -- which is why this tests
        # ``is not None`` rather than truthiness.
        if (
            parent.scope_narrowing is not None
            and child.scope_narrowing is not None
            and not set(child.scope_narrowing) <= set(parent.scope_narrowing)
        ):
            return AccessResult(
                allowed=False,
                reason=f"delegation hop {index + 1} scopes exceed parent delegation",
            )

    return AccessResult(allowed=True)


def _is_within_scope(child_purpose: str, parent_purpose: str) -> bool:
    """Whether a child purpose sits within a parent's scope.

    Three ways in, and the third is the one that matters:

    1. Exactly equal. Delegation without narrowing.
    2. The parent is a glob that matches the child, so ``campaign-*`` admits
       ``campaign-x-overlap``. This is how a parent expresses "any purpose in this
       family".
    3. The child extends the parent on a ``-`` segment boundary, so ``campaign-x``
       admits ``campaign-x-overlap`` but **not** ``campaign-xyz-evil``.

    The third rule exists because a plain prefix test -- the obvious implementation,
    -- accepts
    ``campaign-xyz-evil`` under ``campaign-x``. The two purposes are unrelated; one
    merely starts with the other's characters. Requiring the boundary makes the prefix
    mean what a reader assumes it means.

    Case-sensitive, matching the ``purpose_id`` comparison at resolution and unlike
    both existing glob helpers in this SDK. Both choices deny a mis-cased purpose
    rather than admitting it, which is the direction that matters.
    """
    if child_purpose == parent_purpose:
        return True

    if "*" in parent_purpose:
        return _case_sensitive_glob_match(parent_purpose, child_purpose)

    return child_purpose.startswith(parent_purpose + "-")


def _case_sensitive_glob_match(pattern: str, value: str) -> bool:
    """Glob-match a purpose identifier: ``*`` matches any run of characters.

    Neither existing helper fits, which is why this is here rather than a call to
    one of them. :func:`tolap_core.resolution._compile_source_pattern` expands ``*``
    to ``[^:]*`` for colon-delimited source triples and is case-insensitive;
    :func:`tolap_core.enforcement._pattern_matches` expands it to ``.*`` but is also
    case-insensitive and treats brackets specially. Purpose identifiers are
    hyphen-delimited, not colon-delimited, and must compare case-sensitively -- so
    borrowing either would change the answer. The three dialects are deliberately
    separate rather than unified.

    Implemented by splitting on ``*`` and scanning forward rather than by compiling a
    regex. That is a **deliberate deviation from the .NET reference**, which uses a
    bounded ``Regex`` with a 100 ms match timeout because .NET has one and Python's
    ``re`` does not. A pattern such as ``*a*a*a...-x`` against a long run of ``a``
    backtracks catastrophically under ``re``, and there would be no timeout to catch
    it. This matcher cannot backtrack at all -- each ``*``-separated literal is
    located once, left to right -- so the pathological input returns a non-match in
    linear time instead of relying on a bound to fail closed. The observable
    behaviour is identical for every well-formed pattern, and strictly better for a
    hostile one.

    ``pattern`` must contain at least one ``*``; :func:`_is_within_scope` has already
    handled equality and only reaches here when one is present. There is deliberately
    no guard for the wildcard-free case: it would be unreachable, and unreachable
    defensive code is worse than none -- it reads as a handled case that no test can
    exercise.
    """
    parts = pattern.split("*")
    prefix, suffix = parts[0], parts[-1]
    if not value.startswith(prefix) or not value.endswith(suffix):
        return False

    start = len(prefix)
    end = len(value) - len(suffix)
    if start > end:
        # The anchors overlap, so no assignment of the wildcards can cover the value.
        return False

    for part in parts[1:-1]:
        found = value.find(part, start, end)
        if found < 0:
            return False
        start = found + len(part)

    return True
