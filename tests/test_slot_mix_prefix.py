from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_prefix import initial_belief, successors


def test_hidden_ids_cannot_distinguish_the_common_prefix():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    start = initial_belief(game)
    assert start.mask == 3
    branches = successors(game, start)
    assert {branch.mask for branch in branches} == {1, 2}
    assert len({branch.view for branch in branches}) == 2
    assert successors(game, branches[0]) == ()
