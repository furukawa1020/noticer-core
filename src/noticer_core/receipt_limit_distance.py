"""Exact total variation for finite receipt-trace laws."""

from fractions import Fraction

from noticer_core.receipt_limit_projection import Trace


def total_variation(left: dict[Trace, Fraction], right: dict[Trace, Fraction]) -> Fraction:
    """The half-L1 distance, including traces seen on only one side."""
    return sum((
        abs(left.get(key, Fraction()) - right.get(key, Fraction()))
        for key in left.keys() | right.keys()
    ), Fraction()) / 2
