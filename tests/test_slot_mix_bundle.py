from noticer_core.slot_mix_bundle import export_bundle, parse_bundle
from noticer_core.slot_mix_certificate import verify_mix
from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_frontier import WorkBudget
from noticer_core.slot_mix_solve import solve_mix


def test_certificate_survives_an_independent_portable_roundtrip():
    game = asymmetric_game()
    original = solve_mix(game).certificate
    assert original is not None
    raw = export_bundle(game, original)
    decoded_game, decoded = parse_bundle(raw)
    assert verify_mix(decoded_game, decoded, WorkBudget(1000))
    assert decoded == original
    assert export_bundle(decoded_game, decoded) == raw
