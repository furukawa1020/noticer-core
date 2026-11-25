"""Record common support before reporting matched action-stratum effects."""

from collections.abc import Mapping, Set
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StratumSupport:
    stratum: str
    matched: int
    baseline_only: int
    treatment_only: int

    @property
    def comparable(self) -> bool:
        return self.matched > 0


def assess_stratum_support(
    baseline: Mapping[str, Set[str]], treatment: Mapping[str, Set[str]]
) -> tuple[StratumSupport, ...]:
    """Do not pool different action semantics when pair support is absent."""
    strata = baseline.keys() | treatment.keys()
    if not strata or "" in strata:
        raise ValueError("at least one nonempty action stratum is required")
    results = []
    for stratum in sorted(strata):
        left = baseline.get(stratum, frozenset())
        right = treatment.get(stratum, frozenset())
        if "" in left or "" in right:
            raise ValueError("empty pair identifiers are not allowed")
        results.append(
            StratumSupport(stratum, len(left & right), len(left - right), len(right - left))
        )
    return tuple(results)
