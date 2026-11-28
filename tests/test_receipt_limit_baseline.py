from fractions import Fraction

from noticer_core.receipt_limit_baseline import common_complete_baseline
from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer


def test_complete_only_baseline_keeps_or_spends_its_budget():
    game = crossed_recipients()
    observer = Observer(frozenset({"receiver-a"}))
    assert common_complete_baseline(game, observer, Fraction()) == 0
    assert common_complete_baseline(game, observer, Fraction(1, 4)) == Fraction(1, 4)
    adapted = crossed_recipients((1,), (0, 1))
    assert common_complete_baseline(adapted, observer, Fraction()) == 1
