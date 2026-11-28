import pytest

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer, check_observer
from noticer_core.shared_slot_contract import SharedSlotCase


def test_observer_does_not_assume_unknown_receiver_is_silent():
    empty = SharedSlotCase((0,), ())
    problem = ReceiptProblem((empty, empty), ())
    check_observer(problem, Observer(frozenset()))
    with pytest.raises(ValueError):
        check_observer(problem, Observer(frozenset({"unknown"})))
