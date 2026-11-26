"""Exhaust every distinct nonempty last-slot eligibility class in two strata."""

from fractions import Fraction
from itertools import combinations
from typing import Any

from noticer_core.slot_mix_baselines import iterative_profile, uniform_success
from noticer_core.slot_mix_fixtures import last_slot_game
from noticer_core.slot_mix_solve import solve_mix


def compare_incidence_grid() -> dict[str, dict[str, Any]]:
    """Report every verified tie, improvement, and non-result."""
    results: dict[str, dict[str, Any]] = {}
    for n in (3, 4):
        data = dict(
            cases=0, verified=0, ties_uniform=0, beats_uniform=0, ties_iterative=0,
            beats_iterative=0, iterative_gap_above_1_16=0, inconclusive=0,
            deterministic_zero=0,
        )
        gap = Fraction()
        histogram: dict[str, int] = {}
        for rows in combinations(range(1, 1 << n), n):
            data["cases"] += 1
            result = solve_mix(last_slot_game(n, rows))
            if result.status == "inconclusive":
                data["inconclusive"] += 1
                continue
            if result.status != "verified" or result.certificate is None:
                raise RuntimeError("unverified grid result")
            data["verified"] += 1
            masks = tuple(item.mask for item in result.frontier)
            deterministic = (1 << n) - 1 in masks
            data["deterministic_zero"] += not deterministic
            value = result.certificate.value
            histogram[str(value)] = histogram.get(str(value), 0) + 1
            uniform = uniform_success(masks, n)
            iterative = min(iterative_profile(masks, n))
            if value < max(uniform, iterative):
                raise RuntimeError("baseline exceeds the certified upper bound")
            data["ties_uniform" if value == uniform else "beats_uniform"] += 1
            data["ties_iterative" if value == iterative else "beats_iterative"] += 1
            data["iterative_gap_above_1_16"] += value - iterative > Fraction(1, 16)
            gap = max(gap, value - iterative)
        results[str(n)] = {**data, "max_iterative_gap": str(gap), "optimum_histogram": histogram}
    return results
