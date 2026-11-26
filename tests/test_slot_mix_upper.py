from fractions import Fraction

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import WorkBudget
from noticer_core.slot_mix_upper import best_weighted_policy


def test_skewed_weights_do_not_act_as_a_universal_upper_bound_of_one_half():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    fair = Fraction(1, 2), Fraction(1, 2)
    skew = Fraction(3, 4), Fraction(1, 4)
    assert best_weighted_policy(game, fair, WorkBudget(1000)) == Fraction(1, 2)
    assert best_weighted_policy(game, skew, WorkBudget(1000)) == Fraction(3, 4)
