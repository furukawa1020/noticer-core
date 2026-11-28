from fractions import Fraction

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def test_common_complete_trace_preserves_both_goals():
    game = crossed_recipients((1,), (0, 1))
    joint = Observer(frozenset({"receiver-a", "receiver-b"}))
    result = solve_receipts(game, joint, Fraction())
    assert result.certificate is not None and result.certificate.value == 1
