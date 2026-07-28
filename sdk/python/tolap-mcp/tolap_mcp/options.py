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
    default_deny: bool = True
    audit_access: bool = True
    allowed_tools: list[str] = field(default_factory=list)
