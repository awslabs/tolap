from __future__ import annotations


class StaticIdentityResolver:
    """Static identity resolver for testing.

    Allows pre-configuring user groups and roles.
    """

    def __init__(
        self,
        groups: dict[str, list[str]] | None = None,
        roles: dict[str, list[str]] | None = None,
    ) -> None:
        self._groups: dict[str, list[str]] = groups or {}
        self._roles: dict[str, list[str]] = roles or {}

    def get_groups(self, user_id: str) -> list[str]:
        return self._groups.get(user_id, [])

    def get_roles(self, user_id: str) -> list[str]:
        return self._roles.get(user_id, [])

    def add_user_groups(self, user_id: str, groups: list[str]) -> None:
        self._groups[user_id] = groups

    def add_user_roles(self, user_id: str, roles: list[str]) -> None:
        self._roles[user_id] = roles
