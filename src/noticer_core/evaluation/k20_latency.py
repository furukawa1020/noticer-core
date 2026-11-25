"""End-to-end action latency, separating completed and missing observations."""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActionTiming:
    action_id: str
    accepted_ns: int
    completed_ns: int | None


@dataclass(frozen=True, slots=True)
class LatencySummary:
    accepted: int
    completed: int
    unobserved: int
    p50_ns: int | None
    p95_ns: int | None
    max_ns: int | None


def summarize_latency(observations: Iterable[ActionTiming]) -> LatencySummary:
    """Summarize completed actions with nearest-rank empirical quantiles.

    Timestamps must use one monotonic clock. Missing completion observations
    are counted separately and are not zero-latency actions.
    """
    seen: set[str] = set()
    values: list[int] = []
    for item in observations:
        if not item.action_id or item.action_id in seen:
            raise ValueError("action identifiers must be nonempty and unique")
        seen.add(item.action_id)
        if type(item.accepted_ns) is not int or item.accepted_ns < 0:
            raise ValueError("acceptance requires a nonnegative integer clock tick")
        if item.completed_ns is not None:
            if type(item.completed_ns) is not int or item.completed_ns < item.accepted_ns:
                raise ValueError("completion must be an integer clock tick after acceptance")
            values.append(item.completed_ns - item.accepted_ns)
    values.sort()
    count = len(values)
    return LatencySummary(
        len(seen),
        count,
        len(seen) - count,
        values[(count + 1) // 2 - 1] if count else None,
        values[(95 * count + 99) // 100 - 1] if count else None,
        values[-1] if count else None,
    )
