"""Deadline and liveness accounting over promised K20 actions."""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    action_id: str
    accepted_tick: int
    deadline_tick: int
    last_observed_tick: int
    completed_tick: int | None = None


@dataclass(frozen=True, slots=True)
class LivenessSummary:
    promised: int
    on_time: int
    late: int
    overdue: int
    censored: int

    @property
    def conservative_deadline_rate(self) -> float | None:
        """Count only observed on-time actions as successes."""
        return self.on_time / self.promised if self.promised else None


def summarize_liveness(outcomes: Iterable[ActionOutcome]) -> LivenessSummary:
    """Separate late completion, hard misses, and observation ending before the deadline."""
    seen: set[str] = set()
    on_time = late = overdue = censored = 0
    for outcome in outcomes:
        if not outcome.action_id or outcome.action_id in seen:
            raise ValueError("action identifiers must be nonempty and unique")
        seen.add(outcome.action_id)
        accepted, deadline, observed, completed = (
            outcome.accepted_tick, outcome.deadline_tick,
            outcome.last_observed_tick, outcome.completed_tick,
        )
        if any(type(tick) is not int for tick in (accepted, deadline, observed)):
            raise ValueError("observation and deadline ticks must be integers")
        if not 0 <= accepted <= min(deadline, observed):
            raise ValueError("invalid acceptance, deadline or observation ordering")
        if completed is None:
            if observed < deadline:
                censored += 1
            else:
                overdue += 1
        elif type(completed) is not int or not accepted <= completed <= observed:
            raise ValueError("completion is outside the observation window")
        elif completed <= deadline:
            on_time += 1
        else:
            late += 1
    return LivenessSummary(len(seen), on_time, late, overdue, censored)
