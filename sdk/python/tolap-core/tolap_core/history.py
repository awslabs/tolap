"""A bounded, in-order record of recent tool calls (spec section 15.4).

Purpose drift is a property of a sequence, not of a single call. An agent that asks
for one more field each turn is unremarkable at every individual step and obvious
across ten, so a judge given only the current call cannot see the thing it exists to
notice.
"""

from __future__ import annotations

from collections import deque

from tolap_core.judge import DEFAULT_HISTORY_WINDOW


class ToolCallHistory:
    """The sliding window a judge reads its context from.

    Deliberately not persistent and not shared. It holds whatever the caller records,
    which may include argument values, so a process-local buffer that dies with the
    session is the narrowest thing that does the job. An integrator wanting durable
    history should store it themselves, with the retention rules their data demands.

    Not thread-safe. Guard it if a single conversation is driven from several threads;
    the common case is one wrapper serving one conversation.
    """

    def __init__(self, max_size: int = DEFAULT_HISTORY_WINDOW) -> None:
        """Create a history retaining at most ``max_size`` entries.

        ``max_size`` must be at least one: a zero-size window would make
        :meth:`record` a no-op and hand the judge an empty history that looks like a
        fresh conversation, which is precisely the state a drifting agent would
        benefit from. Refused loudly rather than clamped, because clamping to 1 would
        silently give a caller a window they did not ask for.

        Raises:
            ValueError: if ``max_size`` is less than one.
        """
        if max_size < 1:
            raise ValueError(
                f"a tool-call history retains at least one entry, got {max_size}; a "
                "zero-size window silently hands the judge an empty conversation"
            )

        self._max_size = max_size
        self._entries: deque[str] = deque(maxlen=max_size)

    @property
    def max_size(self) -> int:
        """The retention bound."""
        return self._max_size

    def __len__(self) -> int:
        """The number of entries currently retained."""
        return len(self._entries)

    def record(self, tool_call: str) -> None:
        """Record a call, evicting the oldest entry once the window is full.

        Not a set: an agent repeating the same call ten times is a signal, and
        de-duplicating would erase exactly the pattern the judge is looking for.

        Raises:
            ValueError: if ``tool_call`` is None.
        """
        if tool_call is None:
            raise ValueError("a recorded tool call must be a string, not None")

        self._entries.append(tool_call)

    def get_recent(self) -> list[str]:
        """The retained calls, oldest first.

        Oldest first because a judge reading a trajectory needs it in the order it
        happened -- read backwards, a widening sequence looks like a narrowing one,
        which inverts the finding.

        Returns a copy, so a caller holding the result cannot see it change underneath
        them on the next :meth:`record`, and cannot mutate the window by writing into
        what they were handed.
        """
        return list(self._entries)

    def clear(self) -> None:
        """Discard every entry, for reuse across conversations. The bound is kept."""
        self._entries.clear()
