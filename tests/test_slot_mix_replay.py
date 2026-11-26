from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import WorkBudget, build_frontier
from noticer_core.slot_mix_replay import replay_mask


def test_replay_distinguishes_deliveries_from_legal_misses():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    for candidate in build_frontier(game, WorkBudget(1000)):
        assert replay_mask(game, candidate.root) == candidate.mask
