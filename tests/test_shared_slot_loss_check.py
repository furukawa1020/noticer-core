from dataclasses import replace

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_loss_check import verify_game_loss
from noticer_core.shared_slot_strategy import search_strategy


def test_loss_checker_rejects_omitted_moves_and_impossible_observations():
    left, right = crossed_public_futures()
    game = PublicSlotGame((left, right))
    proof = search_strategy(game).loss
    assert proof is not None
    assert verify_game_loss(game, proof)
    assert not verify_game_loss(PublicSlotGame((left,)), proof)
    assert not verify_game_loss(game, replace(proof, rejected=proof.rejected[1:]))
    entry = proof.rejected[0]
    assert entry.child is not None
    fabricated = replace(entry, child=replace(entry.child, observation=(4, ())))
    assert not verify_game_loss(game, replace(proof, rejected=(fabricated, *proof.rejected[1:])))
