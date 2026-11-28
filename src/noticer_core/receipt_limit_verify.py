"""Independently recompute the reachable signatures and check both bounds."""

from dataclasses import dataclass
from fractions import Fraction
from itertools import product

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_distance import total_variation
from noticer_core.receipt_limit_distribution import PlanLaw, summarize_law
from noticer_core.receipt_limit_enumerate import MAX_STEPS, ReceiptCutoff
from noticer_core.receipt_limit_observer import Observer, check_observer
from noticer_core.receipt_limit_projection import Trace


@dataclass(frozen=True)
class ReceiptCertificate:
    """Two achieved unconditional laws and an exact worst-world value."""

    delta: Fraction
    value: Fraction
    laws: tuple[PlanLaw, PlanLaw]


def checked_upper(
    problem: ReceiptProblem, observer: Observer, delta: Fraction, max_steps: int
) -> Fraction:
    """Use a Cartesian enumeration independent of construction and trace grouping."""
    if type(max_steps) is not int or not 0 < max_steps <= MAX_STEPS:
        raise ValueError("invalid checker budget")
    receiver = dict(problem.recipients)
    check_observer(problem, observer)

    def signatures(world_id: int) -> tuple[set[Trace], set[Trace]]:
        world = problem.worlds[world_id]
        good: set[Trace] = set()
        any_trace: set[Trace] = set()
        ordered = tuple(sorted(world.actions, key=lambda action: action.name))
        for i, slots in enumerate(product(*[(-1, *action.slots) for action in ordered])):
            if i >= max_steps:
                raise ReceiptCutoff("independent checker budget exhausted")
            if any(slots.count(slot) > limit for slot, limit in enumerate(world.capacities)):
                continue
            events = []
            for action, slot in zip(ordered, slots, strict=True):
                name = receiver[action.name]
                if slot >= 0 and name in observer.receivers:
                    events.append((slot, name, action.name))
            trace = tuple(sorted(events))
            if -1 not in slots:
                good.add(trace)
            elif observer.announce_failure:
                trace += ((len(world.capacities), "", "failure"),)
            any_trace.add(trace)
        return good, any_trace

    left, available_left = signatures(0)
    right, available_right = signatures(1)
    if not left or not right:
        return Fraction()
    if left & right:
        return Fraction(1)
    if left & available_right and right & available_left:
        return (1 + delta) / 2
    return delta


def verify_receipt_certificate(
    problem: ReceiptProblem, observer: Observer, cert: ReceiptCertificate, max_steps: int
) -> bool:
    """Check the observed TV, achieved guarantee, and independent upper bound."""
    if (
        type(cert.delta) is not Fraction or not 0 <= cert.delta <= 1
        or type(cert.value) is not Fraction or not 0 <= cert.value <= 1
        or type(cert.laws) is not tuple or len(cert.laws) != 2
    ):
        return False
    try:
        left, success_left = summarize_law(problem, observer, 0, cert.laws[0])
        right, success_right = summarize_law(problem, observer, 1, cert.laws[1])
    except (ValueError, TypeError):
        return False
    return (
        total_variation(left, right) <= cert.delta
        and min(success_left, success_right) == cert.value
        and checked_upper(problem, observer, cert.delta, max_steps) == cert.value
    )
