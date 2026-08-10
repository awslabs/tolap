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
    hash_salt: str | bytes | None = None
    """Secret salt for ``hash`` masking, turning the digest into a keyed HMAC.

    Unset by default, which preserves the plain-digest pseudonym (and so existing
    join keys). Set it and ``hash`` becomes a confidentiality control: an unsalted
    digest of a low-entropy value -- an SSN, a date of birth, a small enumeration
    -- is recoverable by brute force or a rainbow table, because the input space is
    small enough to enumerate.

    Treat it as a secret on a par with ``signing_key``: store it in a secrets
    manager or KMS, never in the policy JSON (policies are visible to every admin
    and auditor who can read them). The same salt must be configured everywhere the
    pseudonym is joined, since changing it changes every masked value.
    """
    allow_unenforceable_shapes: bool = False
    """Pass through tool results the policy cannot be applied to.

    Off by default: a scalar, ``None``, a generator, or an arbitrary object is
    denied rather than returned unfiltered. Integrators mid-migration may opt in
    per wrapper, which is logged at WARNING every time it lets a result through.
    """
