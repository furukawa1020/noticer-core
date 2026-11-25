"""Effect sizes in original metric units for paired K20 comparisons."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import fsum, isfinite
from typing import Literal

EffectVerdict = Literal["meaningful", "below-threshold", "inconclusive"]


@dataclass(frozen=True, slots=True)
class PairedEffect:
    pair_ids: tuple[str, ...]
    improvements: tuple[float, ...]
    mean_improvement: float


def paired_effect(
    baseline: Mapping[str, float], treatment: Mapping[str, float], *, lower_is_better: bool
) -> PairedEffect:
    """Define a positive difference as improvement, keeping the metric units."""
    if not baseline or baseline.keys() != treatment.keys() or "" in baseline:
        raise ValueError("pair identifiers must be nonempty and exactly matched")
    keys = tuple(sorted(baseline))
    sign = -1 if lower_is_better else 1
    differences = tuple(sign * (treatment[key] - baseline[key]) for key in keys)
    if not all(isfinite(value) for value in differences):
        raise ValueError("paired differences must be finite")
    mean = fsum(value / len(keys) for value in differences)
    return PairedEffect(keys, differences, mean)


def assess_effect(lower: float, upper: float, *, meaningful: float) -> EffectVerdict:
    """Compare the entire interval to the predeclared improvement threshold."""
    if not all(map(isfinite, (lower, upper, meaningful))) or lower > upper or meaningful <= 0:
        raise ValueError("invalid confidence interval or meaningful effect threshold")
    if lower >= meaningful:
        return "meaningful"
    if upper < meaningful:
        return "below-threshold"
    return "inconclusive"
