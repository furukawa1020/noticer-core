from fractions import Fraction

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_solve import solve_mix


def test_verified_and_cutoff_results_remain_distinct():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    result = solve_mix(game)
    assert result.status == "verified" and result.certificate is not None
    assert result.certificate.value == Fraction(1, 2)
    for limit in (
        {"work_limit": 1}, {"verification_limit": 1}, {"pivot_limit": 1}
    ):
        incomplete = solve_mix(game, **limit)
        assert incomplete.status == "inconclusive"
        assert incomplete.certificate is None and not incomplete.frontier
    assert solve_mix(game, pivot_limit=0).status == "invalid"
