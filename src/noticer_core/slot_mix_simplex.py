"""Bounded rational simplex from a feasible slack basis."""

from dataclasses import dataclass
from fractions import Fraction

from noticer_core.slot_mix_frontier import MixLimit

MAX_PIVOTS = 1024


@dataclass(frozen=True)
class Packing:
    """Optimal primal and dual coefficients of a binary packing LP."""

    tape_weights: tuple[Fraction, ...]
    policy_weights: tuple[Fraction, ...]
    objective: Fraction


def pack_fractionally(masks: tuple[int, ...], tapes: int, max_pivots: int) -> Packing:
    """Maximize total tape mass with unit constraints on winning tape masks."""
    if (
        type(tapes) is not int
        or not 1 <= tapes <= 8
        or not masks
        or len(masks) > 256
        or any(type(mask) is not int or not 0 <= mask < (1 << tapes) for mask in masks)
        or type(max_pivots) is not int
        or not 0 < max_pivots <= MAX_PIVOTS
    ):
        raise ValueError("invalid rational packing dimensions")
    cover = 0
    for mask in masks:
        cover |= mask
    if cover != (1 << tapes) - 1:
        raise ValueError("packing contains an uncovered tape")
    rows = [
        [Fraction(bool(mask & (1 << i))) for i in range(tapes)]
        + [Fraction(i == j) for j in range(len(masks))]
        + [Fraction(1)]
        for i, mask in enumerate(masks)
    ]
    obj = [Fraction(-1)] * tapes + [Fraction()] * (len(masks) + 1)
    basic = list(range(tapes, tapes + len(masks)))
    for pivots in range(max_pivots + 1):
        entering = next((i for i, coefficient in enumerate(obj[:-1]) if coefficient < 0), None)
        if entering is None:
            values = dict(zip(basic, (row[-1] for row in rows), strict=True))
            return Packing(
                tuple(values.get(i, Fraction()) for i in range(tapes)),
                tuple(obj[tapes:-1]),
                obj[-1],
            )
        if pivots == max_pivots:
            raise MixLimit("rational packing pivot budget exhausted")
        leaving = min(
            (i for i, row in enumerate(rows) if row[entering] > 0),
            key=lambda i: (rows[i][-1] / rows[i][entering], basic[i]),
        )
        pivot = rows[leaving][entering]
        rows[leaving] = row = [value / pivot for value in rows[leaving]]
        basic[leaving] = entering
        for i, other in enumerate(rows):
            if i != leaving and other[entering]:
                factor = other[entering]
                rows[i] = [value - factor * x for value, x in zip(other, row, strict=True)]
        multiplier = obj[entering]
        obj = [value - multiplier * x for value, x in zip(obj, row, strict=True)]
    raise AssertionError("terminated simplex loop without a result")
