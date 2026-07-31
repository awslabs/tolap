from __future__ import annotations

from typing import Protocol


class RequestIdentityExtractor(Protocol):
    """Protocol for extracting identity from incoming requests."""

    def extract_user_id(self, request: dict) -> str | None:
        """Extract the user ID from a request."""
        ...

    def extract_tenant_id(self, request: dict) -> str | None:
        """Extract the tenant ID from a request."""
        ...
