from fractions import Fraction
from itertools import product

from noticer_core.shared_slot_game_examples import late_conflict_game, robust_schedule_game
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import WorkBudget, build_frontier
from noticer_core.slot_mix_upper import best_weighted_policy


def test_scalar_dp_agrees_with_success_masks_for_different_multislot_weights():
    for source, numerators in product((late_conflict_game, robust_schedule_game), (1, 2, 3, 4)):
        game = SlotMixGame(source())
        weights = Fraction(numerators, 5), Fraction(5 - numerators, 5)
        masks = [entry.mask for entry in build_frontier(game, WorkBudget(1000))]
        expected = max(sum(weight for i, weight in enumerate(weights) if mask & (1 << i))
                       for mask in masks)
        assert best_weighted_policy(game, weights, WorkBudget(1000)) == expected
