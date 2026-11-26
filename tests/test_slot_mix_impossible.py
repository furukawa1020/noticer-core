from noticer_core.slot_mix_fixtures import last_slot_game
from noticer_core.slot_mix_solve import solve_mix


def test_an_unreachable_tape_prevents_any_positive_guarantee():
    result = solve_mix(last_slot_game(3, (0, 3, 5, 6)))
    assert result.status == "verified" and result.certificate is not None
    assert result.certificate.value == 0
    assert result.certificate.tape_weights == (1, 0, 0, 0)
