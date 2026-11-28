from fractions import Fraction

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def test_single_observer_can_certify_one_half_while_coalition_cannot():
    game = crossed_recipients()
    single = Observer(frozenset({"receiver-a"}))
    joint = Observer(frozenset({"receiver-a", "receiver-b"}))
    for observer, expected in ((single, Fraction(5, 8)), (joint, Fraction(1, 4))):
        result = solve_receipts(game, observer, Fraction(1, 4))
        assert result.certificate is not None and result.certificate.value == expected
