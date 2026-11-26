from dataclasses import replace

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_policy_check import replay_policy, verify_policy
from noticer_core.shared_slot_strategy import search_strategy


def test_single_tape_policy_is_replayed_but_cannot_claim_the_crossed_tape():
    left, right = crossed_public_futures()
    game = PublicSlotGame((left,))
    policy = search_strategy(game).policy
    assert policy is not None
    assert verify_policy(game, policy)
    assert not verify_policy(PublicSlotGame((left, right)), policy)
    assert not verify_policy(game, replace(policy, send=("b", "b")))
    replay = replay_policy(left, policy)
    assert replay is not None
    assert replay[0] == (("a", 1), ("b", 0))
