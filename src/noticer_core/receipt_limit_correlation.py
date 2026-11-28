"""A synthetic control where equal marginals do not imply an equal joint law."""

from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_distance import total_variation
from noticer_core.receipt_limit_distribution import PlanLaw, summarize_law
from noticer_core.receipt_limit_observer import Observer
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def correlation_control() -> tuple[ReceiptProblem, tuple[PlanLaw, PlanLaw]]:
    """Both laws always succeed, but observed correlations differ."""
    tape = SharedSlotCase(
        (2, 2), tuple(SharedAction(name, 1, (0, 1)) for name in ("a", "b"))
    )
    problem = ReceiptProblem((tape, tape), (("a", "alpha"), ("b", "bravo")))
    half = Fraction(1, 2)
    return problem, (
        (((("a", 0), ("b", 0)), half), ((("a", 1), ("b", 1)), half)),
        (((("a", 0), ("b", 1)), half), ((("a", 1), ("b", 0)), half)),
    )


def correlation_distances() -> dict[str, Fraction]:
    """Compare both single-receiver marginals with the coalition transcript."""
    problem, laws = correlation_control()
    distances = {}
    for tag, visible in (
        ("alpha", ("alpha",)), ("bravo", ("bravo",)), ("coalition", ("alpha", "bravo"))
    ):
        observer = Observer(frozenset(visible))
        left, left_success = summarize_law(problem, observer, 0, laws[0])
        right, right_success = summarize_law(problem, observer, 1, laws[1])
        if left_success != 1 or right_success != 1:
            raise AssertionError("correlation control must always deliver")
        distances[tag] = total_variation(left, right)
    return distances
