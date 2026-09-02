"""Rendering a tool call as the one line a semantic judge reasons over."""

from __future__ import annotations

__all__ = ["render_tool_call"]


def render_tool_call(
    tool_name: str,
    object_name: str | None = None,
    fields: list[str] | None = None,
    endpoint_path: str | None = None,
    endpoint_method: str | None = None,
) -> str:
    """Render a call for the judge and for the tool-call history.

    Deterministic, and includes only what the wrapper was given: the tool name, and the
    object, fields and endpoint when present. Field *names* appear because "which columns"
    is most of what makes a read on-purpose or not; field *values* never reach here, so no
    row data is sent to a model by this path.

    Shared with the wrapper rather than reimplemented by an integrator calling
    :func:`evaluate_judge` directly: two renderings of one call would make the wrapper's
    history and a hand-rolled one incomparable, and the history is what the judge uses to
    see drift.
    """
    parts: list[str] = []
    if object_name:
        parts.append(f"object={object_name}")
    if fields:
        parts.append(f"fields=[{','.join(fields)}]")
    if endpoint_path:
        parts.append(f"endpoint={endpoint_method or 'GET'} {endpoint_path}")

    return f"{tool_name}()" if not parts else f"{tool_name}({' '.join(parts)})"
