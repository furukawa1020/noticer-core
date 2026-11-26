from dataclasses import replace

import pytest

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import Choice, WorkBudget, build_frontier
from noticer_core.slot_mix_replay import replay_mask


def test_tape_specific_and_fabricated_children_are_rejected():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    root = build_frontier(game, WorkBudget(1000))[0].root
    for tampered in (
        replace(root, send=("a", "b")),
        replace(root, children=root.children[:1]),
        replace(root, children=(*root.children, Choice((1, ("ghost",)), ()))),
        replace(root, children=(*root.children, root.children[0])),
    ):
        with pytest.raises(ValueError):
            replay_mask(game, tampered)
