"""Exact mixtures over valid schedules with all outcomes retained."""

from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_projection import Trace, project_receipts
from noticer_core.receipt_limit_schedule import Schedule
from noticer_core.slot_mix_probability import is_distribution

PlanLaw = tuple[tuple[Schedule, Fraction], ...]


def summarize_law(
    problem: ReceiptProblem, observer: Observer, world: int, law: PlanLaw
) -> tuple[dict[Trace, Fraction], Fraction]:
    """Aggregate repeated traces and count complete deliveries independently."""
    if not is_distribution(tuple(mass for _, mass in law), len(law)):
        raise ValueError("invalid schedule law")
    traces: dict[Trace, Fraction] = {}
    utility = Fraction()
    for schedule, mass in law:
        trace, complete = project_receipts(problem, world, schedule, observer)
        if mass:
            traces[trace] = traces.get(trace, Fraction()) + mass
        if complete:
            utility += mass
    return traces, utility
