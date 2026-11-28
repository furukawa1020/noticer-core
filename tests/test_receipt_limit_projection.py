from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_projection import project_receipts
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_hidden_receipt_not_visible_but_affects_utility():
    tape = SharedSlotCase((1,), (SharedAction("a", 0, (0,)),))
    problem = ReceiptProblem((tape, tape), (("a", "clinic"),))
    nobody = Observer(frozenset())
    assert project_receipts(problem, 0, (), nobody) == ((), False)
    assert project_receipts(problem, 0, (("a", 0),), nobody) == ((), True)
