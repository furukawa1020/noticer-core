"""Arm-stratified missingness accounting over planned observations."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class Observation(StrEnum):
    COMPLETE = "complete"
    MISSING = "missing"
    CENSORED = "censored"


@dataclass(frozen=True, slots=True)
class Missingness:
    mechanism: str
    condition: str
    total: int
    missing: int
    censored: int


def summarize_missingness(
    cells: Mapping[tuple[str, str], tuple[Observation, ...]]
) -> tuple[Missingness, ...]:
    """Treat each declared list as the full planned denominator for its cell."""
    if not cells:
        raise ValueError("the declared cell inventory must not be empty")
    rows = []
    for (arm, condition), states in sorted(cells.items()):
        if not arm or not condition or not states:
            raise ValueError("each cell needs a mechanism, condition and planned observations")
        if any(not isinstance(state, Observation) for state in states):
            raise ValueError("each observation must have an explicit typed state")
        rows.append(Missingness(
            arm, condition, len(states), states.count(Observation.MISSING),
            states.count(Observation.CENSORED),
        ))
    return tuple(rows)
