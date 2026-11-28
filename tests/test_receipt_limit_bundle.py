from fractions import Fraction

from noticer_core.receipt_limit_bundle import export_certificate, parse_certificate
from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts
from noticer_core.receipt_limit_verify import verify_receipt_certificate


def test_standalone_bundle_roundtrips_input_and_claim():
    game = crossed_recipients()
    view = Observer(frozenset({"receiver-a"}))
    result = solve_receipts(game, view, Fraction(1, 4))
    assert result.certificate is not None
    data = export_certificate(game, view, result.certificate)
    copy, observation, certificate = parse_certificate(data)
    assert verify_receipt_certificate(copy, observation, certificate, 100)
    assert export_certificate(copy, observation, certificate) == data
