from __future__ import annotations

from enum import Enum


class MaskType(Enum):
    full = "full"
    hash = "hash"
    partial = "partial"
    redact = "redact"
    null = "null"

    @property
    def restrictiveness(self) -> int:
        return _MASK_RESTRICTIVENESS[self]


_MASK_RESTRICTIVENESS: dict[MaskType, int] = {
    MaskType.full: 5,
    MaskType.hash: 4,
    MaskType.partial: 3,
    MaskType.redact: 2,
    MaskType.null: 1,
}


class FilterOperator(Enum):
    equals = "equals"
    not_equals = "notEquals"
    in_ = "in"
    not_in = "notIn"
    greater_than = "greaterThan"
    less_than = "lessThan"
    contains = "contains"
    starts_with = "startsWith"
    matches = "matches"


class AssigneeType(Enum):
    user = "user"
    group = "group"
    role = "role"
    service_account = "serviceAccount"


class SigningAlgorithm(Enum):
    hmac_sha256 = "hmac-sha256"
    hmac_sha512 = "hmac-sha512"
    ed25519 = "ed25519"
