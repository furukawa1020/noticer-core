import pytest

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame


def test_game_conditioned_on_equal_initial_observation_accepts_two_futures():
    left, right = crossed_public_futures()
    game = PublicSlotGame((left, right))
    assert game.deadlines == {"a": 1, "b": 1}
    assert game.horizon == 2
    with pytest.raises(ValueError, match="first public view"):
        PublicSlotGame((left, SharedSlotCase((2, 1), right.actions)))
