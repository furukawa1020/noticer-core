from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_both_cutoffs_remain_unverified():
    tape = SharedSlotCase((1, 1), (SharedAction("a", 1, (0, 1)),))
    problem = ReceiptProblem((tape, tape), (("a", "one"),))
    observer = Observer(frozenset({"one"}))
    assert solve_receipts(problem, observer, Fraction()).status == "verified"
    for limits in ({"max_steps": 1}, {"check_steps": 1}):
        result = solve_receipts(problem, observer, Fraction(), **limits)
        assert result.status == "inconclusive" and result.certificate is None
    assert solve_receipts(problem, observer, Fraction(-1)).status == "invalid"
