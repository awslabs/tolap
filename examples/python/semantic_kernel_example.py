"""TOLAP enforcement inside a Semantic Kernel plugin.

A plugin is a class whose methods carry ``@kernel_function``. TOLAP goes inside the method, so
the kernel's function metadata and planner behaviour are unchanged.

    python semantic_kernel_example.py

Verified against semantic-kernel 1.44.x.
"""

from __future__ import annotations

from semantic_kernel.functions import kernel_function

from tolap_setup import enforced_query


class PatientsPlugin:
    """A plugin whose single function can only return policy-permitted rows.

    The plugin holds no policy state and takes no credential. That is deliberate: a plugin
    instance is typically registered once on a long-lived kernel and shared across requests, so
    caching a user's context on it would leak one caller's permissions into the next caller's
    request. :func:`enforced_query` resolves and verifies per call instead.
    """

    @kernel_function(
        name="query_patients",
        description="Query a patient table. Returns only what the caller's policy permits.",
    )
    def query_patients(self, table: str) -> list[dict]:
        return enforced_query(table)


def main() -> None:
    plugin = PatientsPlugin()

    rows = plugin.query_patients(table="patients")
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    try:
        plugin.query_patients(table="encounters")
        raise AssertionError("expected the denied table to raise")
    except PermissionError as exc:
        print(f"denied table    -> PermissionError: {str(exc)[:70]}")


if __name__ == "__main__":
    main()
