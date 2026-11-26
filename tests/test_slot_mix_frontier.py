import pytest

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import MixLimit, WorkBudget, build_frontier


def test_frontier_never_chooses_opposite_first_sends_in_the_same_policy():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    result = build_frontier(game, WorkBudget(1000))
    assert [(item.mask, item.root.send) for item in result] == [(1, ("b",)), (2, ("a",))]
    with pytest.raises(MixLimit):
        build_frontier(game, WorkBudget(1))
