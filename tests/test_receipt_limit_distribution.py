from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_distribution import summarize_law
from noticer_core.receipt_limit_observer import Observer
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_distribution_does_not_condition_on_success():
    world = SharedSlotCase((1,), (SharedAction("a", 0, (0,)),))
    game = ReceiptProblem((world, world), (("a", "clinic"),))
    half = Fraction(1, 2)
    traces, utility = summarize_law(
        game, Observer(frozenset()), 0, (((), half), ((("a", 0),), half))
    )
    assert traces == {(): 1}
    assert utility == half
