from dataclasses import replace
from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_verify import ReceiptCertificate, verify_receipt_certificate
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_valid_bound_requires_an_achieving_law():
    a = SharedSlotCase((1, 1), (SharedAction("a", 1, (0,)),))
    b = SharedSlotCase((1, 1), (SharedAction("a", 1, (1,)),))
    problem = ReceiptProblem((a, b), (("a", "one"),))
    observer = Observer(frozenset({"one"}))
    zero = ReceiptCertificate(Fraction(), Fraction(), ((((), Fraction(1)),),) * 2)
    assert verify_receipt_certificate(problem, observer, zero, 100)
    assert not verify_receipt_certificate(problem, observer, replace(zero, value=Fraction(1)), 100)
