"""Resolving a call's action category from wrapper configuration (spec section 15.2).

Two lookups rather than one, because the two wrapper families identify a call
differently. An MCP-style tool has a name. An HTTP request has a method and a path and
no name at all -- :meth:`tolap_mcp.SecureHttpToolWrapper.request` carries no tool
identifier -- so a single name-keyed map would mean this enforcement point silently
never ran for API sources. A gate that does not exist is worse than no gate, because
the configuration implies one does.

The maps are configuration on the wrapper, set by whoever deploys it. They are
deliberately not policy fields and deliberately not caller arguments: an agent that
can name its own action category can name an allowed one, which turns the whole check
into a formality.

Lives in ``tolap_core`` rather than in the wrappers so that both wrappers, in all
three SDKs, share one fail-closed rule and one set of tests -- and because the
endpoint glob dialect it needs is private to this package.
"""

from __future__ import annotations

from typing import Mapping

from tolap_core.enforcement import AccessResult, _pattern_matches, validate_action
from tolap_core.models import EffectivePolicy, PurposeProfile


UNDECLARED_CATEGORY_REASON = "action category not declared for tool"
"""The denial for a call whose category cannot be determined under a constraining purpose.

Part of the contract; integrators log and branch on it. Phrased as a configuration
problem rather than an access problem, because that is what it is: the fix is to add
the tool to the map, not to widen the policy.
"""


def validate_tool_action(
    policy: EffectivePolicy,
    tool_name: str,
    tool_action_categories: Mapping[str, str] | None,
) -> AccessResult:
    """Validate a named tool call against the policy's purpose.

    ``policy`` with no purpose profile always allows -- the short-circuit is on the
    profile rather than on the map, which is what keeps a purpose-agnostic deployment
    behaving exactly as it did before this feature.

    ``tool_action_categories`` maps tool name to action category and is supplied by
    the integrator. Matched exactly and case-sensitively, as ``allowed_tools`` is: a
    tool name is an identifier, not a pattern.
    """
    profile = policy.purpose_profile
    if profile is None:
        return AccessResult(allowed=True)

    if tool_action_categories is not None and tool_name in tool_action_categories:
        return validate_action(tool_action_categories[tool_name], profile)

    return _unclassified_result(profile)


def validate_http_action(
    policy: EffectivePolicy,
    method: str,
    path: str,
    http_action_categories: Mapping[str, str] | None,
) -> AccessResult:
    """Validate an HTTP request against the policy's purpose.

    ``http_action_categories`` keys have the form ``"METHOD path-glob"`` -- for
    example ``"GET /segments/*"`` -- mapped to an action category. The method is
    compared case-insensitively, matching how ``allowed_methods`` is compared; the
    path is matched with the same glob dialect ``allowed_endpoints`` uses, so a
    deployment writes one kind of endpoint pattern rather than two.

    ``path`` is the request path with the query string already stripped, so a
    category cannot be dodged by appending one.

    When several entries match, **all** of them are validated and the first denial is
    returned. Picking a single "best" match would need a specificity rule, and any
    such rule can be gamed by adding a broader entry; evaluating every match makes the
    outcome independent of ordering and of how the map happens to be written. Keys are
    considered in sorted order so the reason string is stable.
    """
    profile = policy.purpose_profile
    if profile is None:
        return AccessResult(allowed=True)

    matched = False

    if http_action_categories is not None:
        for key in sorted(http_action_categories):
            if not _key_matches(key, method, path):
                continue

            matched = True
            result = validate_action(http_action_categories[key], profile)
            if not result.allowed:
                return result

    return AccessResult(allowed=True) if matched else _unclassified_result(profile)


def _unclassified_result(profile: PurposeProfile) -> AccessResult:
    """What to do with a call no map entry classified.

    Denied whenever the purpose constrains actions at all -- whether by an allow-list
    or by a non-empty deny-list. The deny-list case is the less obvious half and the
    more important one: a purpose declaring only ``prohibited_actions:
    ["export_pii"]`` means "anything but exporting PII", and an unclassified tool might
    be an exporter. Letting it through because no rule named it would permit the
    unclassified while forbidding the classified, which cannot be what the author
    meant.

    An empty ``prohibited_actions`` restricts nothing, so it does not make a call
    unclassifiable -- mirroring the null-versus-empty rule in spec section 3, where
    the two arrays read in opposite directions.
    """
    constrains_actions = (
        profile.allowed_actions is not None or bool(profile.prohibited_actions)
    )

    return (
        AccessResult(allowed=False, reason=UNDECLARED_CATEGORY_REASON)
        if constrains_actions
        else AccessResult(allowed=True)
    )


def _key_matches(key: str, method: str, path: str) -> bool:
    """Whether a ``"METHOD path-glob"`` key covers this request.

    A key with no space, or with an empty method or an empty pattern, matches
    nothing. It is a misconfiguration, and a key that silently matched everything
    would be the worst possible reading of one -- the map exists to narrow.
    """
    separator = key.find(" ")
    if separator <= 0 or separator == len(key) - 1:
        return False

    return key[:separator].upper() == method.upper() and _pattern_matches(
        key[separator + 1 :], path
    )
