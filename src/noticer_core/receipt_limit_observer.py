"""Declare which receivers share decoded application receipts."""

from dataclasses import dataclass

from noticer_core.receipt_limit_contract import ReceiptProblem


@dataclass(frozen=True)
class Observer:
    """A recipient subset; failures may optionally be publicly announced."""

    receivers: frozenset[str]
    announce_failure: bool = False


def check_observer(problem: ReceiptProblem, observer: Observer) -> None:
    """An empty receiver set is allowed; an unknown receiver is invalid."""
    known = {receiver for _, receiver in problem.recipients}
    if (
        type(observer) is not Observer
        or type(observer.receivers) is not frozenset
        or not observer.receivers <= known
        or type(observer.announce_failure) is not bool
    ):
        raise ValueError("invalid observer")
