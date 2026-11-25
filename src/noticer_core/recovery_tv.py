"""Exact finite total variation for individual and joint observer alphabets."""

from collections import Counter
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from fractions import Fraction


@dataclass(frozen=True, slots=True)
class ObserverVariation:
    marginals: tuple[Fraction, ...]
    joint: Fraction


def _tv(left: Counter, right: Counter) -> Fraction:
    first, second = left.total(), right.total()
    return sum(
        (abs(Fraction(left[key], first) - Fraction(right[key], second))
         for key in left.keys() | right.keys()),
        Fraction(),
    ) / 2


def observer_variation(
    left: Sequence[tuple[Hashable, ...]], right: Sequence[tuple[Hashable, ...]]
) -> ObserverVariation:
    """Use complete uniform finite alphabets, not fitted predictions."""
    if not left or not right or not left[0]:
        raise ValueError("both finite settings need observations and observer columns")
    width = len(left[0])
    if any(len(row) != width for sample in (left, right) for row in sample):
        raise ValueError("observers must be aligned in both worlds")
    return ObserverVariation(
        tuple(_tv(Counter(row[i] for row in left), Counter(row[i] for row in right))
              for i in range(width)),
        _tv(Counter(left), Counter(right)),
    )
