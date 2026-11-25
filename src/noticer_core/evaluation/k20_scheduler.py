"""Deterministic matched jobs for a frozen K20 comparison matrix."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from noticer_core.evaluation.k20_seeds import build_seed_ledger


@dataclass(frozen=True, slots=True)
class ScheduledPair:
    pair_id: str
    workload_id: str
    repetition: int
    seed: int
    mechanism_ids: tuple[str, ...]


def schedule_pairs(
    workloads: Sequence[str],
    mechanisms: Sequence[str],
    *,
    repetitions: int,
    root_seed: int,
) -> tuple[ScheduledPair, ...]:
    """Give every mechanism in a pair the same workload and external randomness seed."""
    if not workloads or len(set(workloads)) != len(workloads):
        raise ValueError("workload identifiers must be nonempty and distinct")
    if len(mechanisms) < 2 or len(set(mechanisms)) != len(mechanisms) or "" in mechanisms:
        raise ValueError("at least two distinct named mechanisms are required")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if len(workloads) * len(mechanisms) * repetitions > 100_000:
        raise ValueError("comparison matrix exceeds the scheduling work bound")
    pairs = tuple(
        (f"pair/{workload}/{repetition}", workload, repetition)
        for workload in sorted(workloads)
        for repetition in range(repetitions)
    )
    if "" in workloads:
        raise ValueError("workload identifier must not be empty")
    ledger = dict(build_seed_ledger(root_seed, (pair[0] for pair in pairs)).entries)
    names = tuple(sorted(mechanisms))
    return tuple(
        ScheduledPair(key, workload, repetition, ledger[key], names)
        for key, workload, repetition in pairs
    )


def require_paired_coverage(
    schedule: Sequence[ScheduledPair], outcomes: Mapping[tuple[str, str], str]
) -> None:
    """Require an explicit state for each run, including failures and censoring."""
    expected = {(pair.pair_id, name) for pair in schedule for name in pair.mechanism_ids}
    allowed = {"completed", "failed", "invalid", "inconclusive"}
    if not expected or expected != outcomes.keys() or not set(outcomes.values()) <= allowed:
        raise ValueError("outcomes must describe every scheduled run exactly once")
