"""Group legal plan witnesses by the observer's decoded receipt trace."""

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_enumerate import enumerate_schedules
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_projection import Trace, project_receipts
from noticer_core.receipt_limit_schedule import Schedule

Classes = dict[Trace, dict[bool, Schedule]]


def trace_classes(
    problem: ReceiptProblem, observer: Observer, world: int, max_steps: int
) -> Classes:
    """Retain one valid plan per observable class and complete-delivery bit."""
    classes: Classes = {}
    for schedule in enumerate_schedules(problem.worlds[world], max_steps=max_steps):
        trace, complete = project_receipts(problem, world, schedule, observer)
        classes.setdefault(trace, {}).setdefault(complete, schedule)
    return classes
