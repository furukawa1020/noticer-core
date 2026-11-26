from fractions import Fraction

from noticer_core.shared_slot_policy_check import observed
from noticer_core.slot_mix_memory_fixture import reconverging_game
from noticer_core.slot_mix_replay import replay_choice
from noticer_core.slot_mix_solve import solve_mix


def test_public_history_can_resolve_conflict_even_when_current_views_reconverge():
    game = reconverging_game()
    left, right = game.public.tapes
    assert observed(left, 1) != observed(right, 1)
    assert observed(left, 2) == observed(right, 2)
    result = solve_mix(game)
    assert result.certificate is not None and result.certificate.value == Fraction(1)
    policy = result.certificate.policies[0].root
    left_win, left_path = replay_choice(left, policy)
    right_win, right_path = replay_choice(right, policy)
    assert left_win and right_win
    assert left_path[2].send == ("b",) and right_path[2].send == ("a",)
