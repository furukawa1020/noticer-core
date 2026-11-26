"""Exact dummy requirement for padding already-fixed frame allocations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverWitness:
    """A common count shape and its exact dummy count per input allocation."""

    shape: tuple[int, ...]
    dummies: tuple[int, ...]


def fixed_allocation_cover(counts: tuple[tuple[int, ...], ...]) -> CoverWitness:
    """Each slot requires the pointwise maximum for fixed real-frame counts.

    Does not optimize assignments or account for wire bytes, acknowledgments, or RTT.
    """
    if not counts or not counts[0] or any(
        len(trace) != len(counts[0])
        or any(type(count) is not int or count < 0 for count in trace)
        for trace in counts
    ):
        raise ValueError("invalid frame counts")
    shape = tuple(map(max, zip(*counts, strict=True)))
    return CoverWitness(shape, tuple(sum(shape) - sum(trace) for trace in counts))
