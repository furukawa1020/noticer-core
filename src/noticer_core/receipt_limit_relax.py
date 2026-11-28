"""Construct the optimal relaxation using unconditional total variation."""

from fractions import Fraction

from noticer_core.receipt_limit_classes import Classes
from noticer_core.receipt_limit_distribution import PlanLaw
from noticer_core.receipt_limit_exact import exact_pair_law


def construct_laws(
    left: Classes, right: Classes, delta: Fraction
) -> tuple[Fraction, tuple[PlanLaw, PlanLaw]]:
    """Reserve delta mass for a pair of complete schedules if both exist."""
    if type(delta) is not Fraction or not 0 <= delta <= 1:
        raise ValueError("invalid variation bound")
    exact, shared = exact_pair_law(left, right)
    complete_left = next((c[True] for c in left.values() if True in c), None)
    complete_right = next((c[True] for c in right.values() if True in c), None)
    if complete_left is None or complete_right is None:
        return Fraction(), ((((), Fraction(1)),), (((), Fraction(1)),))
    if exact == 1:
        delta = Fraction()
    pairs = [(pair, mass * (1 - delta)) for pair, mass in shared if mass * (1 - delta)]
    if delta:
        pairs.append(((complete_left, complete_right), delta))
    return (
        (1 - delta) * exact + delta,
        (
            tuple((pair[0], mass) for pair, mass in pairs),
            tuple((pair[1], mass) for pair, mass in pairs),
        ),
    )
