from noticer_core.receipt_limit_classes import trace_classes
from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_same_observable_class_can_contain_success_and_failure():
    tape = SharedSlotCase((1,), (SharedAction("a", 0, (0,)),))
    problem = ReceiptProblem((tape, tape), (("a", "clinic"),))
    classes = trace_classes(problem, Observer(frozenset()), 0, 100)
    assert set(classes[()]) == {False, True}
