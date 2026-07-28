from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class PolicyAuditEvent:
    """Represents an auditable event in the policy store."""

    event_type: str
    timestamp: str
    details: str
    user_id: str | None = None
    policy_name: str | None = None
    assignee_identifier: str | None = None

    @classmethod
    def create(
        cls,
        event_type: str,
        details: str,
        policy_name: str | None = None,
        assignee_identifier: str | None = None,
        user_id: str | None = None,
    ) -> PolicyAuditEvent:
        return cls(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            details=details,
            user_id=user_id,
            policy_name=policy_name,
            assignee_identifier=assignee_identifier,
        )
