from noticer_core.shared_slot_first import verify_public_futures
from noticer_core.shared_slot_game_examples import late_conflict_game, robust_schedule_game
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_loss_check import verify_game_loss
from noticer_core.shared_slot_policy_check import replay_policy, verify_policy
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_strategy import search_strategy


def test_robust_policy_matches_offline_on_both_admitted_tapes():
    game = robust_schedule_game()
    policy = search_strategy(game).policy
    assert policy is not None and policy.send == ("b",)
    assert verify_policy(game, policy)
    for tape, baseline_count in zip(game.tapes, (3, 2), strict=True):
        replay = replay_policy(tape, policy)
        assert replay is not None
        assert len(replay[0]) == len(solve_shared_slots(tape).placements) == 3
        assert len(deadline_first(tape)) == baseline_count


def test_common_offline_first_choice_does_not_imply_a_later_causal_choice():
    game = late_conflict_game()
    first = verify_public_futures(*game.tapes)
    assert first.left & first.right == {"start"}
    result = search_strategy(game).loss
    assert result is not None and verify_game_loss(game, result)
    forced = next(entry for entry in result.rejected if entry.send == ("start",))
    assert forced.child is not None and forced.child.slot == 1
