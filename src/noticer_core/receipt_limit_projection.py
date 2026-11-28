"""Logical receiver trace: ordered slot, receiver, action plus optional status."""

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer, check_observer
from noticer_core.receipt_limit_schedule import Schedule, schedule_success

Trace = tuple[tuple[int, str, str], ...]


def project_receipts(
    problem: ReceiptProblem, world_id: int, schedule: Schedule, observer: Observer
) -> tuple[Trace, bool]:
    """Return the observable trace and a distinct utility bit."""
    check_observer(problem, observer)
    if type(world_id) is not int or world_id not in (0, 1):
        raise ValueError("invalid history")
    complete = schedule_success(problem.worlds[world_id], schedule)
    receivers = dict(problem.recipients)
    events = tuple(sorted(
        (slot, receivers[action], action)
        for action, slot in schedule if receivers[action] in observer.receivers
    ))
    if observer.announce_failure and not complete:
        events += ((len(problem.worlds[world_id].capacities), "", "failure"),)
    return events, complete
