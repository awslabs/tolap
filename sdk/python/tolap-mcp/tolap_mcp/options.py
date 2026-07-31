from __future__ import annotations

from dataclasses import dataclass, field

from tolap_core.enums import SigningAlgorithm


@dataclass
class SecureMcpServerOptions:
    """Configuration options for the secure MCP tool wrapper."""

    signing_key: str
    signing_algorithm: SigningAlgorithm = SigningAlgorithm.hmac_sha256
    enforce_signatures: bool = True
    enforce_expiry: bool = True
    allowed_tools: list[str] = field(default_factory=list)
    allow_unenforceable_shapes: bool = False
    """Pass through tool results the policy cannot be applied to.

    Off by default: a scalar, ``None``, a generator, or an arbitrary object is
    denied rather than returned unfiltered. Integrators mid-migration may opt in
    per wrapper, which is logged at WARNING every time it lets a result through.
    """
