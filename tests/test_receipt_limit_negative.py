from fractions import Fraction

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def test_even_full_leakage_does_not_rescue_an_unreachable_world():
    game = crossed_recipients((), (0,))
    result = solve_receipts(game, Observer(frozenset()), Fraction(1))
    assert result.certificate is not None and result.certificate.value == 0
