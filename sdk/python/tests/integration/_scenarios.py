"""Helpers for loading shared cross-SDK integration scenarios.

Scenarios live in `fixtures/integration-scenarios/*.json` and are consumed by
all three SDKs. Python's loader builds a `SecurityContext` from each scenario's
policy, signs it with the test signing key, and returns it alongside the
expected outcome so tests can stay declarative.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from tolap_core.context import build_security_context, sign_context
from tolap_core.serialization import deserialize_effective_policy
from tolap_core.models import EffectivePolicy, SecurityContext


SCENARIOS_DIR = Path(__file__).parents[4] / "fixtures" / "integration-scenarios"

# SQL identifiers (table/column names) in these tests come from the checked-in
# fixture files, but we still validate them against a strict allow-list before
# interpolating into any statement. This is defense-in-depth: it guarantees a
# stray or malformed fixture value can never become SQL, and keeps the raw-SQL
# used by the test harness demonstrably injection-free.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


def safe_identifier(name: str) -> str:
    """Return ``name`` if it is a valid SQL identifier, else raise ValueError."""
    if not isinstance(name, str) or not _IDENTIFIER_RE.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def load_scenarios(filename: str) -> dict:
    return json.loads((SCENARIOS_DIR / filename).read_text())


def merge_policy(base: dict, override: dict | None) -> dict:
    """Shallow-merge an override dict into a base policy dict.

    Only top-level keys are merged; nested objects are replaced wholesale.
    Sufficient for the current scenarios; revisit if scenarios grow more
    complex overrides.
    """
    if not override:
        return base
    merged = dict(base)
    for k, v in override.items():
        merged[k] = v
    return merged


def policy_from_dict(policy_dict: dict) -> EffectivePolicy:
    return deserialize_effective_policy(policy_dict)


def sign_policy(
    policy: EffectivePolicy,
    signing_key: str,
    *,
    user_id: str = "scenario-user",
    tenant_id: str = "scenario-tenant",
    ttl: timedelta = timedelta(hours=1),
) -> SecurityContext:
    ctx = build_security_context(user_id, tenant_id, [policy], ttl=ttl)
    return sign_context(ctx, signing_key)
