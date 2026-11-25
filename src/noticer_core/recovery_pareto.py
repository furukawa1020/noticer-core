"""Separate feasible tradeoffs from failed or unresolved recovery candidates."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class EvidenceStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class RecoveryCost:
    name: str
    status: EvidenceStatus
    misses: int
    states: int
    delay_slots: int
    bytes_sent: int

    @property
    def axes(self) -> tuple[int, int, int]:
        return self.states, self.delay_slots, self.bytes_sent


@dataclass(frozen=True, slots=True)
class RecoveryFrontier:
    nondominated: tuple[str, ...]
    dominated: tuple[str, ...]
    ineligible: tuple[str, ...]


def recovery_frontier(runs: Iterable[RecoveryCost]) -> RecoveryFrontier:
    """Use only verified, deadline-feasible candidates on a common workload."""
    ordered = tuple(sorted(runs, key=lambda run: run.name))
    if not ordered or len({run.name for run in ordered}) != len(ordered):
        raise ValueError("provide a nonempty set of uniquely named recovery candidates")
    for run in ordered:
        metric_values = (run.misses, *run.axes)
        if not run.name or not isinstance(run.status, EvidenceStatus):
            raise ValueError("candidate names and status must be explicit")
        if any(type(value) is not int or value < 0 for value in metric_values) or run.states == 0:
            raise ValueError("invalid cost or state count")
    feasible = tuple(
        run for run in ordered if run.status is EvidenceStatus.VERIFIED and run.misses == 0
    )
    dominated = {
        run.name
        for run in feasible
        if any(
            other.axes != run.axes
            and all(a <= b for a, b in zip(other.axes, run.axes, strict=True))
            for other in feasible
        )
    }
    return RecoveryFrontier(
        tuple(run.name for run in feasible if run.name not in dominated),
        tuple(sorted(dominated)),
        tuple(run.name for run in ordered if run not in feasible),
    )
