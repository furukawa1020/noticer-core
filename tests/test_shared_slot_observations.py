from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_observations import refine_tapes


def test_root_coalesces_tapes_and_next_public_observation_splits_them():
    game = PublicSlotGame(crossed_public_futures())
    assert refine_tapes(game, (0, 1), 0) == (((1, ("a", "b")), (0, 1)),)
    assert refine_tapes(game, (0, 1), 1) == (((1, ("a",)), (0,)), ((1, ("b",)), (1,)))
    assert refine_tapes(game, (1,), 1) == (((1, ("b",)), (1,)),)
