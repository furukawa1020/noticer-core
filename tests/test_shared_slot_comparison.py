from noticer_core.shared_slot_comparison import compare_finite_grid, worst_slack_first
from noticer_core.shared_slot_game_examples import robust_schedule_game
from noticer_core.shared_slot_verify import verify_assignment


def test_uncertainty_aware_heuristic_ties_the_checked_hedge_fixture():
    game = robust_schedule_game()
    for index, tape in enumerate(game.tapes):
        placements = worst_slack_first(game, index)
        assert ("b", 0) in placements
        assert verify_assignment(tape, placements)


def test_grid_keeps_all_denominators_and_preserves_the_information_ceiling():
    grid = compare_finite_grid()
    for row in grid.values():
        assert row["tape_pairs"] == 136
        assert row["tape_pairs"] == (
            row["checked_policy"] + row["checked_no_policy"] + row["inconclusive"]
        )
        assert row["checked_policy"] <= row["offline_both"] <= row["tape_pairs"]
        assert row["deadline_first_both"] <= row["checked_policy"]
        assert row["worst_slack_both"] <= row["checked_policy"]
