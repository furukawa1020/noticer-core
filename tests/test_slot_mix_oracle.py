from itertools import combinations

from noticer_core.slot_mix_fixtures import last_slot_game
from noticer_core.slot_mix_frontier import WorkBudget, build_frontier
from noticer_core.slot_mix_replay import replay_mask


def test_public_frontier_equals_direct_last_action_enumeration():
    for rows in combinations(range(1, 8), 3):
        game = last_slot_game(3, rows)
        actual = build_frontier(game, WorkBudget(1000))
        outcomes = {
            sum(1 << i for i, row in enumerate(rows) if row & (1 << action))
            for action in range(3)
        }
        expected = {mask for mask in outcomes if not any(
            mask != other and mask & other == mask for other in outcomes
        )}
        assert {item.mask for item in actual} == expected
        assert all(replay_mask(game, item.root) == item.mask for item in actual)
