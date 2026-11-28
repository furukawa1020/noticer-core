from fractions import Fraction

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def test_attaching_an_observable_failure_bit_changes_the_bound():
    game = crossed_recipients()
    visible = frozenset({"receiver-a"})
    for announce, expected in ((False, Fraction(1, 2)), (True, Fraction())):
        result = solve_receipts(game, Observer(visible, announce), Fraction())
        assert result.certificate is not None and result.certificate.value == expected
