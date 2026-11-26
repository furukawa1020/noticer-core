"""Emit checked evidence for finite public-information-set synthesis."""

from dataclasses import asdict
from typing import Any

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_game_examples import late_conflict_game, robust_schedule_game
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_loss_check import verify_game_loss
from noticer_core.shared_slot_policy_check import replay_policy, verify_policy
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_strategy import search_strategy


def build_checked_game_report() -> dict[str, Any]:
    """Preserve costs, impossibility, and budget failures in one output."""
    fixtures = (
        ("robust_hedge", robust_schedule_game()),
        ("late_conflict", late_conflict_game()),
        ("crossed_futures", PublicSlotGame(crossed_public_futures())),
    )
    rows: dict[str, Any] = {}
    for name, game in fixtures:
        result = search_strategy(game)
        row: dict[str, Any] = {
            "status": result.status,
            "moves_examined": result.moves_examined,
            "deadline_first": tuple(len(deadline_first(tape)) for tape in game.tapes),
            "offline": tuple(len(solve_shared_slots(tape).placements) for tape in game.tapes),
            "required": len(game.deadlines),
        }
        if result.policy is not None:
            if not verify_policy(game, result.policy):
                raise RuntimeError("independent policy replay failed")
            replays = [replay_policy(tape, result.policy) for tape in game.tapes]
            row.update({
                "status": "verified_policy",
                "certificate": asdict(result.policy),
                "causal": tuple(len(replay[0]) for replay in replays if replay is not None),
            })
        elif result.loss is not None:
            if not verify_game_loss(game, result.loss):
                raise RuntimeError("independent loss check failed")
            row.update({"status": "verified_no_policy", "certificate": asdict(result.loss)})
        rows[name] = row
    return {
        "schema": "shared-capacity-public-game.v1",
        "empirical": False,
        "scenarios": rows,
        "controls": {
            "forced_cutoff": search_strategy(fixtures[1][1], max_moves=1).status,
            "invalid_budget": search_strategy(fixtures[1][1], max_moves=0).status,
        },
    }
