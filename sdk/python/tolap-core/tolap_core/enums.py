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
        return mask_restrictiveness(self)


# Ranked by how much of the original value is disclosed (canonical spec section 6):
# partial leaks real characters, hash is irreversible but joinable, full leaks the
# length, redact leaks nothing, null leaks not even the field's presence. Higher
# rank wins a merge, so null/redact beat partial rather than losing to it.
_MASK_RESTRICTIVENESS: dict[MaskType, int] = {
    MaskType.partial: 1,
    MaskType.hash: 2,
    MaskType.full: 3,
    MaskType.redact: 4,
    MaskType.null: 5,
}

# An unrecognized mask type (typo, or a newer schema version) must never be beaten
# by a known-but-weaker type, so it ranks above every value above.
_UNKNOWN_MASK_RESTRICTIVENESS = max(_MASK_RESTRICTIVENESS.values()) + 1


def mask_restrictiveness(mask_type: object) -> int:
    """Rank a mask type by how little of the value it discloses (higher = stricter).

    Anything that is not a known MaskType ranks most restrictive so that merging
    can never downgrade an unknown mask into a weaker known one.
    """
    if isinstance(mask_type, MaskType):
        return _MASK_RESTRICTIVENESS[mask_type]
    return _UNKNOWN_MASK_RESTRICTIVENESS


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
