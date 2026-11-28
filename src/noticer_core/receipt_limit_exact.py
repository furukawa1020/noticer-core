"""Construct a joint plan law that shares precisely the observable trace."""

from fractions import Fraction

from noticer_core.receipt_limit_classes import Classes
from noticer_core.receipt_limit_schedule import Schedule

Pair = tuple[Schedule, Schedule]
PairLaw = tuple[tuple[Pair, Fraction], ...]


def exact_pair_law(left: Classes, right: Classes) -> tuple[Fraction, PairLaw]:
    """Find value 0, 1/2, or 1 on shared observable traces."""
    directions: dict[bool, Pair] = {}
    one = Fraction(1)
    for trace in sorted(left.keys() & right.keys()):
        a, b = left[trace], right[trace]
        if True in a and True in b:
            return one, (((a[True], b[True]), one),)
        if True in a and False in b:
            directions.setdefault(True, (a[True], b[False]))
        if False in a and True in b:
            directions.setdefault(False, (a[False], b[True]))
    if len(directions) == 2:
        half = Fraction(1, 2)
        return half, ((directions[True], half), (directions[False], half))
    return Fraction(), ((((), ()), one),)
