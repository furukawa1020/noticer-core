"""Complete-common-trace then silence/full baseline, using the same inputs."""

from fractions import Fraction

from noticer_core.receipt_limit_classes import trace_classes
from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_enumerate import MAX_STEPS
from noticer_core.receipt_limit_observer import Observer


def common_complete_baseline(
    problem: ReceiptProblem, observer: Observer, delta: Fraction
) -> Fraction:
    """If no common complete trace, trade at most delta of silence for full sends."""
    left, right = (
        {trace for trace, plans in trace_classes(problem, observer, world, MAX_STEPS).items()
         if True in plans}
        for world in (0, 1)
    )
    if not left or not right:
        return Fraction()
    return Fraction(1) if left & right else delta
