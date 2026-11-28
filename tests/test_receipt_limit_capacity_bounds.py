from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_ceiling_case_is_bounded_and_does_not_promote_truncation():
    names = ("a", "b", "c", "d", "e")
    world = SharedSlotCase(
        (5, 5, 5, 5, 5), tuple(SharedAction(name, 4, tuple(range(5))) for name in names)
    )
    problem = ReceiptProblem((world, world), tuple((name, "one") for name in names))
    observer = Observer(frozenset({"one"}))
    assert solve_receipts(problem, observer, Fraction(), check_steps=7775).status == "inconclusive"
    verified = solve_receipts(problem, observer, Fraction(), check_steps=7776)
    assert verified.certificate is not None and verified.certificate.value == 1
