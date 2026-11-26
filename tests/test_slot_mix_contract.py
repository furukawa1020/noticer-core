import pytest

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame


def test_comparison_counts_distinct_tapes():
    left, right = crossed_public_futures()
    assert len(SlotMixGame(PublicSlotGame((left, right))).public.tapes) == 2
    with pytest.raises(ValueError, match="duplicate"):
        SlotMixGame(PublicSlotGame((left, left)))
