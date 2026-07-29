"""Cross-SDK parity for write protection (canonical spec section 9).

One policy, one method table, asserted with identical expected outcomes in all
three SDKs. The counterparts are:

- TypeScript: ``packages/core/tests/write-protection-parity.test.ts``
- .NET: ``tests/Tolap.Core.Tests/WriteProtectionParityTests.cs``

The table is deliberately mixed so a single divergence in either control is
visible: the policy grants ``DELETE`` and ``POST`` while declaring itself
read-only (so the ``readOnly`` ceiling must override them), omits ``HEAD`` and
``OPTIONS`` from an otherwise present ``allowedMethods`` (so the read methods are
not implicitly re-added), and spells one request method in lower case (so the
comparison must be case-insensitive).

The two denial reasons are asserted, not just the boolean. They must stay
distinguishable across languages, because "method not allowed" is fixed by
widening ``allowedMethods`` and "method not allowed on a read-only policy" is
fixed by clearing ``readOnly`` -- an integrator who cannot tell them apart cannot
tell which policy edit will unblock them.

Both controls previously failed OPEN in all three SDKs, and did so
*inconsistently* once partially fixed, which is the divergence class this file
guards.
"""

from __future__ import annotations

import pytest

from tolap_core.enforcement import validate_endpoint
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    ObjectRules,
    PolicyPermissions,
)

# The shared parity policy. Identical field-for-field in all three SDKs.
PARITY_POLICY = EffectivePolicy(
    version="1.0",
    user_id="parity-user",
    tenant_id="parity-tenant",
    source_profiles=["write-protection-parity"],
    permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
    object_rules=ObjectRules(
        endpoint_rules=EndpointRules(
            allowed_endpoints=["/api/*"],
            hidden_endpoints=["/api/admin/*"],
            allowed_methods=["GET", "POST", "DELETE"],
        )
    ),
)

# (path, method, allowed, reason) -- the canonical table.
PARITY_TABLE = [
    ("/api/x", "GET", True, None),
    ("/api/x", "get", True, None),
    ("/api/x", "HEAD", False, "method not allowed"),
    ("/api/x", "OPTIONS", False, "method not allowed"),
    ("/api/x", "POST", False, "method not allowed on a read-only policy"),
    ("/api/x", "delete", False, "method not allowed on a read-only policy"),
    ("/api/x", "PUT", False, "method not allowed"),
    ("/api/admin/y", "GET", False, "endpoint is hidden"),
    ("/other/z", "GET", False, "endpoint not in allowed set"),
]


@pytest.mark.parametrize(("path", "method", "allowed", "reason"), PARITY_TABLE)
def test_write_protection_parity(
    path: str, method: str, allowed: bool, reason: str | None
) -> None:
    result = validate_endpoint(path, method, PARITY_POLICY)

    assert result.allowed is allowed
    assert result.reason == reason
