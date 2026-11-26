from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_strategy import search_strategy


def test_search_separates_winning_and_losing_prefixes_and_cutoffs():
    left, right = crossed_public_futures()
    loss = search_strategy(PublicSlotGame((left, right)))
    assert loss.status == "no_candidate"
    assert loss.loss is not None and loss.policy is None
    assert {move.send for move in loss.loss.rejected} == {(), ("a",), ("b",)}

    win = search_strategy(PublicSlotGame((left, left)))
    assert win.status == "candidate"
    assert win.policy is not None and win.loss is None
    assert win.policy.send == ("b",)

    cutoff = search_strategy(PublicSlotGame((left, right)), max_moves=1)
    assert cutoff.status == "inconclusive" and cutoff.loss is None and cutoff.policy is None
    assert search_strategy(PublicSlotGame((left,)), max_moves=0).status == "invalid"
