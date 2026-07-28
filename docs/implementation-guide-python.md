# TOLAP Implementation Guide -- Python

This guide walks through implementing TOLAP (Tool-Object Level Access Protocol) in Python. All examples are concrete, runnable Python 3.10+ code. For the canonical schema definitions, see the [Policy Definition Schema](schema/v1.0/policy-definition.schema.json) and [Policy Assignment Schema](schema/v1.0/policy-assignment.schema.json). For the architecture overview, see [architecture.md](architecture.md).

## Prerequisites

Before implementing TOLAP, you need:

1. **Python 3.10+** -- the code uses `match` statements, `dataclasses`, and modern type hints.
2. **An authenticated user identity** -- TOLAP does not handle authentication. Your system must provide a verified user ID and tenant ID.
3. **A policy store** -- Somewhere to persist policy definitions and assignments (database, configuration files, policy service).
4. **A tool layer** -- The tools your AI agents use to access data sources (MCP servers, LangChain tools, CrewAI tools, Strands tools, etc.).

**Standard library only.** The core implementation uses only Python standard library modules (`dataclasses`, `typing`, `enum`, `hmac`, `hashlib`, `json`, `base64`, `datetime`, `uuid`, `abc`, `asyncio`, `fnmatch`). Your data source connectors will need their own drivers (e.g., `asyncpg`, `httpx`, `boto3`).

## Step 1: Define Your Policy Store

TOLAP policies are defined using the [Policy Definition Schema](schema/v1.0/policy-definition.schema.json) and linked to users via the [Policy Assignment Schema](schema/v1.0/policy-assignment.schema.json).

Your policy store needs two collections:

**Policy Definitions** -- reusable rule sets:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID


class MaskType(Enum):
    NULL = "null"
    REDACT = "redact"
    PARTIAL = "partial"
    HASH = "hash"
    FULL = "full"


class FilterOperator(Enum):
    EQUALS = "equals"
    NOT_EQUALS = "notEquals"
    IN = "in"
    NOT_IN = "notIn"
    GREATER_THAN = "greaterThan"
    LESS_THAN = "lessThan"
    CONTAINS = "contains"
    STARTS_WITH = "startsWith"
    BETWEEN = "between"
    IS_NULL = "isNull"
    IS_NOT_NULL = "isNotNull"


@dataclass
class MaskedFieldRule:
    field: str
    mask_type: MaskType
    partial_config: Optional[PartialMaskConfig] = None


@dataclass
class PartialMaskConfig:
    visible_prefix: int = 0
    visible_suffix: int = 0
    mask_char: str = "*"


@dataclass
class RowFilter:
    field: str
    operator: FilterOperator
    value: str
    object_pattern: Optional[str] = None


@dataclass
class TagRules:
    allowed_tags: list[str] = field(default_factory=list)
    denied_tags: list[str] = field(default_factory=list)
    require_all_tags: bool = False


@dataclass
class EndpointRules:
    allowed_endpoints: list[str] = field(default_factory=list)
    hidden_endpoints: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=list)


@dataclass
class FieldRules:
    allowed_fields: list[str] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)
    masked_fields: list[MaskedFieldRule] = field(default_factory=list)


@dataclass
class ObjectRules:
    allowed_objects: list[str] = field(default_factory=list)
    hidden_objects: list[str] = field(default_factory=list)
    field_rules: FieldRules = field(default_factory=FieldRules)
    row_filters: list[RowFilter] = field(default_factory=list)
    tag_rules: TagRules = field(default_factory=TagRules)
    endpoint_rules: EndpointRules = field(default_factory=EndpointRules)


@dataclass
class Permissions:
    can_query: bool = True
    can_export: bool = True
    read_only: bool = False


@dataclass
class Limits:
    max_results: Optional[int] = None
    max_query_time_seconds: Optional[int] = None
    min_similarity_score: Optional[float] = None
    max_object_size_bytes: Optional[int] = None


@dataclass
class PolicyDefinition:
    name: str
    description: str = ""
    priority: int = 100
    applies_to_all: bool = False
    source_patterns: list[str] = field(default_factory=list)
    permissions: Permissions = field(default_factory=Permissions)
    object_rules: ObjectRules = field(default_factory=ObjectRules)
    limits: Limits = field(default_factory=Limits)
    is_active: bool = True
```

**Policy Assignments** -- links between policies and users:

```python
class AssigneeType(Enum):
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    SERVICE_ACCOUNT = "serviceAccount"


@dataclass
class PolicyAssignment:
    policy_name: str
    assignee_type: AssigneeType
    assignee_identifier: str
    tenant_id: Optional[UUID] = None
    source_connection_id: Optional[UUID] = None
    active: bool = True
    expires_at: Optional[datetime] = None
    granted_by: str = ""
    granted_at: datetime = field(default_factory=datetime.utcnow)
    reason: str = ""
```

These can live in a relational database, a document store, configuration files, or any persistent storage your system uses.

## Step 2: Implement the Policy Resolution Engine

The Policy Resolution Engine computes the effective policy for a user and data source by merging all applicable policy definitions.

```python
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from fnmatch import fnmatch
from typing import Protocol
from uuid import UUID


class PolicyStore(Protocol):
    """Protocol for loading policies and assignments from your persistence layer."""

    async def load_assignments_for_user(self, user_id: str) -> list[PolicyAssignment]:
        ...

    async def load_assignments_for_groups_and_roles(
        self, identifiers: list[str]
    ) -> list[PolicyAssignment]:
        ...

    async def load_policy_definition(self, policy_name: str) -> Optional[PolicyDefinition]:
        ...


class UserDirectory(Protocol):
    """Protocol for resolving a user's group and role memberships."""

    async def get_user_groups(self, user_id: str) -> list[str]:
        ...

    async def get_user_roles(self, user_id: str) -> list[str]:
        ...


@dataclass
class EffectivePolicy:
    source_connection_id: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Permissions (merged via AND / OR)
    can_query: bool = False
    can_export: bool = False
    read_only: bool = True

    # Allowed sets (merged via intersection)
    allowed_objects: list[str] = field(default_factory=list)
    allowed_fields: list[str] = field(default_factory=list)
    allowed_endpoints: list[str] = field(default_factory=list)
    allowed_tags: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=list)

    # Hidden / denied sets (merged via union)
    hidden_objects: list[str] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)
    hidden_endpoints: list[str] = field(default_factory=list)
    denied_tags: list[str] = field(default_factory=list)

    # Row filters (concatenated)
    row_filters: list[RowFilter] = field(default_factory=list)

    # Masked fields (most restrictive per field)
    masked_fields: list[MaskedFieldRule] = field(default_factory=list)

    # Numeric limits (most restrictive)
    max_results: Optional[int] = None
    max_query_time_seconds: Optional[int] = None
    max_object_size_bytes: Optional[int] = None
    min_similarity_score: Optional[float] = None


# Sentinel representing a deny-all policy when no policies apply.
DENY_ALL_POLICY = EffectivePolicy(
    can_query=False,
    can_export=False,
    read_only=True,
)


class PolicyResolutionEngine:
    def __init__(self, store: PolicyStore, directory: UserDirectory) -> None:
        self._store = store
        self._directory = directory

    async def resolve_effective_policy(
        self,
        user_id: str,
        tenant_id: UUID,
        source_connection_id: UUID,
        source_category: str,
        source_namespace: str,
        source_name: str,
    ) -> EffectivePolicy:
        now = datetime.utcnow()

        # 1. Load all active assignments for this user
        user_assignments = await self._store.load_assignments_for_user(user_id)

        # 2. Also load group/role assignments
        user_groups = await self._directory.get_user_groups(user_id)
        user_roles = await self._directory.get_user_roles(user_id)
        group_role_identifiers = user_groups + user_roles
        group_assignments = await self._store.load_assignments_for_groups_and_roles(
            group_role_identifiers
        )
        assignments = user_assignments + group_assignments

        # Filter to active and not expired
        assignments = [
            a
            for a in assignments
            if a.active and (a.expires_at is None or a.expires_at > now)
        ]

        # 3. Narrow to tenant scope
        assignments = [
            a
            for a in assignments
            if a.tenant_id is None or a.tenant_id == tenant_id
        ]

        # 4. Narrow to source scope
        assignments = [
            a
            for a in assignments
            if a.source_connection_id is None
            or a.source_connection_id == source_connection_id
        ]

        # 5. Load referenced policy definitions
        policies: list[PolicyDefinition] = []
        for assignment in assignments:
            policy = await self._store.load_policy_definition(assignment.policy_name)
            if policy is not None and policy.is_active:
                policies.append(policy)

        # 6. Filter to policies that match this source
        source_identifier = f"{source_category}:{source_namespace}:{source_name}"
        policies = [
            p
            for p in policies
            if p.applies_to_all
            or any(fnmatch(source_identifier, pattern) for pattern in p.source_patterns)
        ]

        # 7. Sort by priority (lower number = higher precedence)
        policies.sort(key=lambda p: p.priority)

        # 8. Merge using most-restrictive-wins
        return merge_policies(policies)
```

### The Merge Algorithm

```python
from __future__ import annotations


def merge_policies(policies: list[PolicyDefinition]) -> EffectivePolicy:
    if not policies:
        return DENY_ALL_POLICY

    result = EffectivePolicy()

    # Permissions: AND (all must allow) / OR (any sets read-only)
    result.can_query = all(p.permissions.can_query for p in policies)
    result.can_export = all(p.permissions.can_export for p in policies)
    result.read_only = any(p.permissions.read_only for p in policies)

    # Allowed sets: INTERSECTION (only policies that define the field participate)
    result.allowed_objects = _intersect_optional(
        [p.object_rules.allowed_objects for p in policies]
    )
    result.allowed_fields = _intersect_optional(
        [p.object_rules.field_rules.allowed_fields for p in policies]
    )
    result.allowed_endpoints = _intersect_optional(
        [p.object_rules.endpoint_rules.allowed_endpoints for p in policies]
    )
    result.allowed_tags = _intersect_optional(
        [p.object_rules.tag_rules.allowed_tags for p in policies]
    )
    result.allowed_methods = _intersect_optional(
        [p.object_rules.endpoint_rules.allowed_methods for p in policies]
    )

    # Hidden / denied sets: UNION
    result.hidden_objects = _union(
        [p.object_rules.hidden_objects for p in policies]
    )
    result.hidden_fields = _union(
        [p.object_rules.field_rules.hidden_fields for p in policies]
    )
    result.hidden_endpoints = _union(
        [p.object_rules.endpoint_rules.hidden_endpoints for p in policies]
    )
    result.denied_tags = _union(
        [p.object_rules.tag_rules.denied_tags for p in policies]
    )

    # Row filters: concatenate all
    result.row_filters = [
        f for p in policies for f in p.object_rules.row_filters
    ]

    # Masked fields: most restrictive mask type per field
    result.masked_fields = _merge_masked_fields(policies)

    # Numeric limits: minimum (most restrictive)
    result.max_results = _min_optional(
        [p.limits.max_results for p in policies]
    )
    result.max_query_time_seconds = _min_optional(
        [p.limits.max_query_time_seconds for p in policies]
    )
    result.max_object_size_bytes = _min_optional(
        [p.limits.max_object_size_bytes for p in policies]
    )

    # Similarity score: maximum (most restrictive -- higher threshold is stricter)
    result.min_similarity_score = _max_optional(
        [p.limits.min_similarity_score for p in policies]
    )

    return result


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _intersect_optional(sets: list[list[str]]) -> list[str]:
    """Intersect only the non-empty lists.

    If a policy omits a field (empty list), it means 'no restriction from
    this policy'. Only policies that explicitly define the list participate
    in the intersection. If no policies define the list, the result is
    unrestricted (empty list).
    """
    non_empty = [set(s) for s in sets if s]
    if not non_empty:
        return []
    result = non_empty[0]
    for s in non_empty[1:]:
        result = result & s
    return sorted(result)


def _union(sets: list[list[str]]) -> list[str]:
    """Union all lists, deduplicating."""
    combined: set[str] = set()
    for s in sets:
        combined.update(s)
    return sorted(combined)


_MASK_RESTRICTIVENESS: dict[MaskType, int] = {
    MaskType.NULL: 1,
    MaskType.REDACT: 2,
    MaskType.PARTIAL: 3,
    MaskType.HASH: 4,
    MaskType.FULL: 5,
}


def _merge_masked_fields(policies: list[PolicyDefinition]) -> list[MaskedFieldRule]:
    """For each field, pick the most restrictive mask type across all policies."""
    by_field: dict[str, list[MaskedFieldRule]] = {}
    for policy in policies:
        for rule in policy.object_rules.field_rules.masked_fields:
            by_field.setdefault(rule.field, []).append(rule)

    result: list[MaskedFieldRule] = []
    for _field, rules in by_field.items():
        most_restrictive = max(
            rules, key=lambda r: _MASK_RESTRICTIVENESS.get(r.mask_type, 0)
        )
        result.append(most_restrictive)
    return result


def _min_optional(values: list[Optional[int | float]]) -> Optional[int | float]:
    """Return the minimum of all non-None values, or None if all are None."""
    defined = [v for v in values if v is not None]
    return min(defined) if defined else None


def _max_optional(values: list[Optional[int | float]]) -> Optional[float]:
    """Return the maximum of all non-None values, or None if all are None."""
    defined = [v for v in values if v is not None]
    return max(defined) if defined else None
```

**Handling omitted fields:** When a policy omits an optional field (e.g., `allowed_objects` is an empty list), treat it as "no restriction from this policy" for intersection operations. Only policies that explicitly define a field participate in the intersection. If no policies define the field, the effective value is "unrestricted."

## Step 3: Build and Sign the Security Context

The Security Context packages the effective policies and transports them to the tool execution environment.

```python
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional
from uuid import UUID

# Default context TTL -- keep short to limit the replay window.
CONTEXT_TTL = timedelta(hours=1)


@dataclass
class IntegrityBlock:
    algorithm: str = "hmac-sha256"
    signature: str = ""


@dataclass
class SecurityContext:
    user_id: str = ""
    tenant_id: Optional[UUID] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    policies: list[EffectivePolicy] = field(default_factory=list)
    integrity: IntegrityBlock = field(default_factory=IntegrityBlock)


# ---------------------------------------------------------------------------
# JSON serialization helpers (handles UUID, datetime, Enum)
# ---------------------------------------------------------------------------

class _PolicyEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def _serialize_context(context: SecurityContext, *, exclude_integrity: bool = False) -> bytes:
    """Deterministic JSON serialization of the security context."""
    data = asdict(context)
    if exclude_integrity:
        data.pop("integrity", None)
    return json.dumps(data, cls=_PolicyEncoder, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Build, sign, serialize, deserialize
# ---------------------------------------------------------------------------

def build_security_context(
    user_id: str,
    tenant_id: UUID,
    accessible_sources: list[SourceInfo],
    engine: PolicyResolutionEngine,
) -> SecurityContext:
    """Resolve effective policies for all accessible sources and package them."""
    import asyncio

    now = datetime.utcnow()
    context = SecurityContext(
        user_id=user_id,
        tenant_id=tenant_id,
        issued_at=now,
        expires_at=now + CONTEXT_TTL,
    )

    async def _resolve_all() -> list[EffectivePolicy]:
        tasks = [
            engine.resolve_effective_policy(
                user_id=user_id,
                tenant_id=tenant_id,
                source_connection_id=src.connection_id,
                source_category=src.category,
                source_namespace=src.namespace,
                source_name=src.name,
            )
            for src in accessible_sources
        ]
        return await asyncio.gather(*tasks)

    effective_policies = asyncio.run(_resolve_all())

    for src, policy in zip(accessible_sources, effective_policies):
        policy.source_connection_id = src.connection_id
        policy.resolved_at = now
        policy.expires_at = context.expires_at
        context.policies.append(policy)

    return context


@dataclass
class SourceInfo:
    connection_id: UUID
    category: str
    namespace: str
    name: str


def sign_context(context: SecurityContext, secret_key: bytes) -> SecurityContext:
    """Compute an HMAC-SHA256 signature over the context (excluding the integrity block)."""
    payload = _serialize_context(context, exclude_integrity=True)
    signature = hmac.new(secret_key, payload, hashlib.sha256).digest()
    context.integrity = IntegrityBlock(
        algorithm="hmac-sha256",
        signature=base64.b64encode(signature).decode(),
    )
    return context


def serialize_for_transport(context: SecurityContext) -> str:
    """Serialize the signed context to a base64-encoded string for transport."""
    payload = _serialize_context(context, exclude_integrity=False)
    return base64.b64encode(payload).decode()


def deserialize_and_validate(serialized: str, secret_key: bytes) -> SecurityContext:
    """Deserialize a transported context and validate its expiry and signature."""
    raw = base64.b64decode(serialized)
    data = json.loads(raw)

    # Reconstruct the context
    context = _dict_to_security_context(data)

    # Validate expiry
    if context.expires_at is not None and context.expires_at < datetime.utcnow():
        raise ValueError("Security context has expired")

    # Validate signature
    payload = _serialize_context(context, exclude_integrity=True)
    expected_signature = hmac.new(secret_key, payload, hashlib.sha256).digest()
    expected_b64 = base64.b64encode(expected_signature).decode()
    if not hmac.compare_digest(context.integrity.signature, expected_b64):
        raise ValueError("Security context signature is invalid")

    return context


def _dict_to_security_context(data: dict[str, Any]) -> SecurityContext:
    """Reconstruct a SecurityContext from a deserialized dict.

    In production, use a library like ``dacite`` or ``pydantic`` for robust
    deserialization. This minimal implementation covers the critical fields.
    """
    context = SecurityContext(
        user_id=data.get("user_id", ""),
        tenant_id=UUID(data["tenant_id"]) if data.get("tenant_id") else None,
        issued_at=datetime.fromisoformat(data["issued_at"]) if data.get("issued_at") else None,
        expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
        integrity=IntegrityBlock(
            algorithm=data.get("integrity", {}).get("algorithm", "hmac-sha256"),
            signature=data.get("integrity", {}).get("signature", ""),
        ),
    )
    for p in data.get("policies", []):
        ep = EffectivePolicy(
            source_connection_id=UUID(p["source_connection_id"]) if p.get("source_connection_id") else None,
            can_query=p.get("can_query", False),
            can_export=p.get("can_export", False),
            read_only=p.get("read_only", True),
            allowed_objects=p.get("allowed_objects", []),
            hidden_objects=p.get("hidden_objects", []),
            allowed_fields=p.get("allowed_fields", []),
            hidden_fields=p.get("hidden_fields", []),
            row_filters=[
                RowFilter(
                    field=f["field"],
                    operator=FilterOperator(f["operator"]),
                    value=f["value"],
                    object_pattern=f.get("object_pattern"),
                )
                for f in p.get("row_filters", [])
            ],
            masked_fields=[
                MaskedFieldRule(
                    field=m["field"],
                    mask_type=MaskType(m["mask_type"]),
                )
                for m in p.get("masked_fields", [])
            ],
            max_results=p.get("max_results"),
            max_query_time_seconds=p.get("max_query_time_seconds"),
            max_object_size_bytes=p.get("max_object_size_bytes"),
            min_similarity_score=p.get("min_similarity_score"),
        )
        context.policies.append(ep)
    return context
```

**Context TTL guidance:** Keep the TTL short (15 minutes to 1 hour). Shorter TTLs reduce the replay window but require more frequent policy resolution. For same-process execution, the context can be passed in memory without serialization.

## Step 4: Implement Secure Tool Wrappers

Each Secure Tool Wrapper wraps a data source and enforces the effective policy. Here is a base class and a database-specific example:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol
from uuid import UUID


class DataSource(Protocol):
    """Protocol that every data source driver must satisfy."""

    async def execute(self, query: str) -> list[dict[str, Any]]:
        ...

    async def list_objects(self) -> list[str]:
        ...

    async def describe_object(self, object_name: str) -> list[str]:
        ...


class SecureToolWrapper(ABC):
    """Base class for all secure tool wrappers.

    Subclasses implement source-specific query parsing and filter injection.
    The base class handles common permission checks, field masking, and
    result limiting.
    """

    def __init__(self, data_source: DataSource) -> None:
        self._data_source = data_source
        self._policy: Optional[EffectivePolicy] = None
        self._user_id: str = ""
        self._tenant_id: Optional[UUID] = None

    def set_security_context(
        self,
        user_id: str,
        tenant_id: UUID,
        source_connection_id: UUID,
        effective_policy: EffectivePolicy,
    ) -> None:
        self._user_id = user_id
        self._tenant_id = tenant_id
        self._policy = effective_policy

    @property
    def policy(self) -> EffectivePolicy:
        if self._policy is None:
            raise RuntimeError("Security context has not been set")
        return self._policy

    # ------------------------------------------------------------------
    # Query execution with full enforcement
    # ------------------------------------------------------------------

    async def execute_query(self, query: str) -> list[dict[str, Any]]:
        # 1. Check permission
        if not self.policy.can_query:
            raise PermissionError("Access denied: query permission not granted")

        # 2. Validate requested objects
        requested_objects = self.extract_objects_from_query(query)
        for obj in requested_objects:
            if obj in self.policy.hidden_objects:
                raise PermissionError(
                    f"Access denied: object '{obj}' is not accessible"
                )
            if self.policy.allowed_objects and obj not in self.policy.allowed_objects:
                raise PermissionError(
                    f"Access denied: object '{obj}' is not in allowed set"
                )

        # 3. Validate requested fields
        requested_fields = self.extract_fields_from_query(query)
        for fld in requested_fields:
            if fld in self.policy.hidden_fields:
                raise PermissionError(
                    f"Access denied: field '{fld}' is not accessible"
                )

        # 4. Rewrite query with row filters
        for row_filter in self.policy.row_filters:
            query = self.inject_where_clause(query, row_filter)

        # 5. Apply result limit
        if self.policy.max_results is not None:
            query = self.apply_limit(query, self.policy.max_results)

        # 6. Execute against data source
        results = await self._data_source.execute(query)

        # 7. Apply field masking to results
        for row in results:
            for mask_rule in self.policy.masked_fields:
                if mask_rule.field in row:
                    row[mask_rule.field] = apply_mask(
                        row[mask_rule.field], mask_rule
                    )

        return results

    # ------------------------------------------------------------------
    # Schema introspection (filtered)
    # ------------------------------------------------------------------

    async def list_accessible_objects(self) -> list[str]:
        all_objects = await self._data_source.list_objects()
        return [
            obj
            for obj in all_objects
            if obj not in self.policy.hidden_objects
            and (not self.policy.allowed_objects or obj in self.policy.allowed_objects)
        ]

    async def describe_object(self, object_name: str) -> list[str]:
        all_fields = await self._data_source.describe_object(object_name)
        return [
            f
            for f in all_fields
            if f not in self.policy.hidden_fields
            and (not self.policy.allowed_fields or f in self.policy.allowed_fields)
        ]

    # ------------------------------------------------------------------
    # Abstract methods -- subclasses implement source-specific logic
    # ------------------------------------------------------------------

    @abstractmethod
    def extract_objects_from_query(self, query: str) -> list[str]:
        """Parse the query and return the referenced object names."""
        ...

    @abstractmethod
    def extract_fields_from_query(self, query: str) -> list[str]:
        """Parse the query and return the referenced field names."""
        ...

    @abstractmethod
    def inject_where_clause(self, query: str, row_filter: RowFilter) -> str:
        """Rewrite the query to include the given row filter."""
        ...

    @abstractmethod
    def apply_limit(self, query: str, max_results: int) -> str:
        """Rewrite the query to cap the number of returned rows."""
        ...


# ---------------------------------------------------------------------------
# Field masking utility
# ---------------------------------------------------------------------------

def apply_mask(value: Any, rule: MaskedFieldRule) -> Any:
    """Apply the specified mask to a single field value."""
    if value is None:
        return None

    match rule.mask_type:
        case MaskType.NULL:
            return None
        case MaskType.REDACT:
            return "[REDACTED]"
        case MaskType.HASH:
            import hashlib
            return hashlib.sha256(str(value).encode()).hexdigest()
        case MaskType.FULL:
            return "*" * len(str(value))
        case MaskType.PARTIAL:
            text = str(value)
            cfg = rule.partial_config or PartialMaskConfig()
            if len(text) <= cfg.visible_prefix + cfg.visible_suffix:
                return cfg.mask_char * len(text)
            prefix = text[: cfg.visible_prefix]
            suffix = text[-cfg.visible_suffix :] if cfg.visible_suffix > 0 else ""
            masked_len = len(text) - cfg.visible_prefix - cfg.visible_suffix
            return prefix + (cfg.mask_char * masked_len) + suffix
        case _:
            return "[REDACTED]"
```

### Source-Specific Enforcement

Different source categories require different enforcement strategies:

**Database sources:**
- Row filters become SQL WHERE clauses injected into the query
- Hidden columns are validated before query execution (reject queries that reference them)
- Column masking is applied to result rows after execution
- Schema introspection (list tables, describe columns) returns only accessible objects

**API sources:**
- Endpoint access is validated against allowed/hidden endpoint patterns before the HTTP request
- HTTP method is validated against the allowed methods list
- Response fields are masked after the response is received
- Endpoint listing returns only accessible endpoints

**Knowledge base sources:**
- Allowed/denied tags are converted to the vector store's native filter format
- Similarity score threshold is passed to the search request
- Results below the threshold or with denied tags are excluded
- Access info methods return the user's tag permissions

**Storage sources:**
- Allowed/denied prefixes are validated before object access
- File type restrictions are checked before retrieval
- Object size limits are enforced before download
- Object metadata masking is applied to listing results

## Step 5: Implement the Secure Tool Factory

The factory creates initialized Secure Tool Wrapper instances for a user.

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional
from uuid import UUID


class DataSourceRegistry(Protocol):
    """Protocol for looking up data source connection metadata."""

    async def get_connection(self, connection_id: UUID) -> SourceConnection:
        ...


class CredentialResolver(Protocol):
    """Protocol for resolving credentials for a data source."""

    async def resolve(self, source: SourceConnection) -> dict[str, Any]:
        ...


@dataclass
class SourceConnection:
    connection_id: UUID
    source_type: str
    host: str
    port: int = 0
    database: str = ""
    extra: dict[str, str] = field(default_factory=dict)


class SecureToolFactory:
    """Creates secure tool wrappers bound to a user's effective policies."""

    def __init__(
        self,
        policy_engine: PolicyResolutionEngine,
        data_source_registry: DataSourceRegistry,
        credential_resolver: CredentialResolver,
    ) -> None:
        self._engine = policy_engine
        self._registry = data_source_registry
        self._credentials = credential_resolver

    async def create_all_accessible_tools(
        self, security_context: SecurityContext
    ) -> list[SecureToolWrapper]:
        tools: list[SecureToolWrapper] = []

        for policy in security_context.policies:
            if not policy.can_query:
                continue  # Skip sources the user cannot query

            source = await self._registry.get_connection(policy.source_connection_id)
            credentials = await self._credentials.resolve(source)

            wrapper = self._create_wrapper_for_source_type(
                source.source_type, source, credentials
            )
            wrapper.set_security_context(
                user_id=security_context.user_id,
                tenant_id=security_context.tenant_id,
                source_connection_id=policy.source_connection_id,
                effective_policy=policy,
            )
            tools.append(wrapper)

        return tools

    async def create_tool_for_source(
        self, security_context: SecurityContext, source_connection_id: UUID
    ) -> SecureToolWrapper:
        policy = next(
            (
                p
                for p in security_context.policies
                if p.source_connection_id == source_connection_id
            ),
            None,
        )
        if policy is None:
            raise LookupError(
                f"No policy found for source: {source_connection_id}"
            )

        source = await self._registry.get_connection(source_connection_id)
        credentials = await self._credentials.resolve(source)

        wrapper = self._create_wrapper_for_source_type(
            source.source_type, source, credentials
        )
        wrapper.set_security_context(
            user_id=security_context.user_id,
            tenant_id=security_context.tenant_id,
            source_connection_id=source_connection_id,
            effective_policy=policy,
        )
        return wrapper

    @staticmethod
    def _create_wrapper_for_source_type(
        source_type: str,
        source: SourceConnection,
        credentials: dict[str, Any],
    ) -> SecureToolWrapper:
        match source_type:
            case "postgresql" | "mysql" | "sqlserver" | "athena":
                return SecureDatabaseWrapper(source, credentials)
            case "rest" | "graphql" | "soap" | "fhir" | "grpc":
                return SecureApiWrapper(source, credentials)
            case "bedrock-kb" | "opensearch" | "elasticsearch":
                return SecureKnowledgebaseWrapper(source, credentials)
            case "s3" | "azure-blob" | "gcs":
                return SecureStorageWrapper(source, credentials)
            case _:
                raise ValueError(f"Unsupported source type: {source_type}")
```

## Step 6: Wire It Together

Here is the complete flow from request to results:

```python
from __future__ import annotations

import asyncio
from uuid import UUID

# Assume these are initialized with your concrete implementations:
# policy_store: PolicyStore
# user_directory: UserDirectory
# data_source_registry: DataSourceRegistry
# credential_resolver: CredentialResolver
# SIGNING_KEY: bytes

SIGNING_KEY = b"your-secret-signing-key"


async def handle_agent_request(
    authenticated_user_id: str,
    tenant_id: UUID,
    request: str,
    *,
    policy_store: PolicyStore,
    user_directory: UserDirectory,
    data_source_registry: DataSourceRegistry,
    credential_resolver: CredentialResolver,
) -> str:
    engine = PolicyResolutionEngine(policy_store, user_directory)

    # 1. Resolve policies and build security context
    accessible_sources = await get_accessible_sources(
        authenticated_user_id, tenant_id
    )
    context = build_security_context(
        authenticated_user_id, tenant_id, accessible_sources, engine
    )
    signed_context = sign_context(context, SIGNING_KEY)

    # 2. If executing in a different process/service, serialize for transport
    # serialized = serialize_for_transport(signed_context)
    # ... send via queue, header, or RPC ...
    # signed_context = deserialize_and_validate(serialized, SIGNING_KEY)

    # 3. Create secure tools
    factory = SecureToolFactory(engine, data_source_registry, credential_resolver)
    tools = await factory.create_all_accessible_tools(signed_context)

    # 4. Give tools to the agent runtime
    agent = create_agent(tools)
    result = await agent.execute(request)

    return result
```

The agent receives tools that can only return data the user is authorized to see. The agent does not need to know about security policies, check permissions, or filter results. Enforcement is invisible and non-bypassable.

## Testing Recommendations

### Unit Tests for Policy Resolution

Test the merge algorithm with multiple overlapping policies:

- Two policies with overlapping `allowed_fields` -- verify intersection
- One policy hides a field, another allows it -- verify hidden wins
- Two policies with different `max_results` -- verify minimum wins
- One policy sets `can_query = False` -- verify AND produces `False`
- Policy with row filters from multiple profiles -- verify all filters are present

```python
import pytest


def test_allowed_fields_intersection() -> None:
    p1 = PolicyDefinition(
        name="policy-a",
        object_rules=ObjectRules(
            field_rules=FieldRules(allowed_fields=["name", "email", "age"])
        ),
    )
    p2 = PolicyDefinition(
        name="policy-b",
        object_rules=ObjectRules(
            field_rules=FieldRules(allowed_fields=["email", "age", "address"])
        ),
    )
    result = merge_policies([p1, p2])
    assert set(result.allowed_fields) == {"email", "age"}


def test_hidden_fields_union() -> None:
    p1 = PolicyDefinition(
        name="policy-a",
        object_rules=ObjectRules(
            field_rules=FieldRules(hidden_fields=["ssn"])
        ),
    )
    p2 = PolicyDefinition(
        name="policy-b",
        object_rules=ObjectRules(
            field_rules=FieldRules(hidden_fields=["salary"])
        ),
    )
    result = merge_policies([p1, p2])
    assert set(result.hidden_fields) == {"ssn", "salary"}


def test_max_results_takes_minimum() -> None:
    p1 = PolicyDefinition(name="policy-a", limits=Limits(max_results=1000))
    p2 = PolicyDefinition(name="policy-b", limits=Limits(max_results=500))
    result = merge_policies([p1, p2])
    assert result.max_results == 500


def test_can_query_requires_all() -> None:
    p1 = PolicyDefinition(
        name="policy-a", permissions=Permissions(can_query=True)
    )
    p2 = PolicyDefinition(
        name="policy-b", permissions=Permissions(can_query=False)
    )
    result = merge_policies([p1, p2])
    assert result.can_query is False


def test_row_filters_concatenated() -> None:
    p1 = PolicyDefinition(
        name="policy-a",
        object_rules=ObjectRules(
            row_filters=[RowFilter(field="dept", operator=FilterOperator.EQUALS, value="sales")]
        ),
    )
    p2 = PolicyDefinition(
        name="policy-b",
        object_rules=ObjectRules(
            row_filters=[RowFilter(field="region", operator=FilterOperator.EQUALS, value="us")]
        ),
    )
    result = merge_policies([p1, p2])
    assert len(result.row_filters) == 2


def test_no_policies_returns_deny_all() -> None:
    result = merge_policies([])
    assert result.can_query is False
    assert result.can_export is False
    assert result.read_only is True
```

### Integration Tests for Tool Wrappers

Test enforcement at the tool level:

- Query referencing a hidden column -- verify rejection
- Query without row filters -- verify filters are injected
- Result with masked fields -- verify masking is applied
- Schema introspection -- verify hidden objects/fields are absent
- Expired security context -- verify rejection

```python
@pytest.mark.asyncio
async def test_hidden_column_rejected() -> None:
    wrapper = build_test_wrapper(
        effective_policy=EffectivePolicy(
            can_query=True,
            hidden_fields=["ssn"],
        )
    )
    with pytest.raises(PermissionError, match="ssn"):
        await wrapper.execute_query("SELECT ssn FROM patients")


@pytest.mark.asyncio
async def test_field_masking_applied() -> None:
    wrapper = build_test_wrapper(
        effective_policy=EffectivePolicy(
            can_query=True,
            masked_fields=[
                MaskedFieldRule(field="email", mask_type=MaskType.HASH)
            ],
        ),
        mock_results=[{"name": "Alice", "email": "alice@example.com"}],
    )
    results = await wrapper.execute_query("SELECT name, email FROM users")
    assert results[0]["name"] == "Alice"
    assert results[0]["email"] != "alice@example.com"  # hashed


@pytest.mark.asyncio
async def test_expired_context_rejected() -> None:
    import os
    key = os.urandom(32)
    context = SecurityContext(
        user_id="user-1",
        expires_at=datetime(2020, 1, 1),  # already expired
    )
    signed = sign_context(context, key)
    serialized = serialize_for_transport(signed)

    with pytest.raises(ValueError, match="expired"):
        deserialize_and_validate(serialized, key)
```

### End-to-End Tests

Test the full flow from user identity to filtered results:

- User with restrictive policy queries a data source -- verify only authorized data returned
- User with no applicable policies -- verify access denied
- User with expired assignment -- verify access denied
- User with multiple overlapping assignments -- verify most-restrictive merge
