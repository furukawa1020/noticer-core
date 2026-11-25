"""Holm adjustment over a complete frozen family of hypotheses."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True, slots=True)
class CorrectedComparison:
    name: str
    adjusted_p: float
    reject: bool


def holm_adjust(
    expected: Sequence[str], p_values: Mapping[str, float], *, alpha: float = 0.05
) -> tuple[CorrectedComparison, ...]:
    """Reject missing, extra or invalid comparisons; retain declared output order."""
    if not expected or "" in expected or len(set(expected)) != len(expected):
        raise ValueError("the declared hypothesis family must contain distinct names")
    if set(expected) != p_values.keys():
        raise ValueError("p-values must cover the exact declared family")
    if not 0 < alpha < 1 or any(not isfinite(p) or not 0 <= p <= 1 for p in p_values.values()):
        raise ValueError("invalid alpha or p-value")
    adjusted: dict[str, float] = {}
    running = 0.0
    for index, name in enumerate(sorted(expected, key=lambda key: (p_values[key], key))):
        running = max(running, min(1.0, (len(expected) - index) * p_values[name]))
        adjusted[name] = running
    return tuple(CorrectedComparison(name, adjusted[name], adjusted[name] <= alpha)
                 for name in expected)
