"""Deterministic counts for separate tape and horizon axes."""

from typing import Any

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_fixtures import last_slot_game
from noticer_core.slot_mix_solve import solve_mix


def delayed_outage(horizon: int) -> SlotMixGame:
    """Preserve the same last-slot conflict while inserting indistinguishable slots."""
    left_and_right = tuple(
        SharedSlotCase(
            (1, *([0] * (horizon - 2)), 1),
            tuple(
                SharedAction(name, horizon - 1, (0, horizon - 1) if name == last else (0,))
                for name in ("a", "b")
            ),
        ) for last in ("a", "b")
    )
    return SlotMixGame(PublicSlotGame(left_and_right))


def measure_work_counts() -> dict[str, Any]:
    """Count evaluated decisions and unions; retain forced cutoffs."""
    cases = {
        **{f"tapes-{n}": last_slot_game(4, tuple(range(1, n + 1))) for n in (2, 4, 6, 8)},
        **{f"horizon-{n}": delayed_outage(n) for n in (2, 4, 6, 8)},
    }
    result = {}
    for key, game in cases.items():
        measured = solve_mix(game)
        result[key] = {
            "status": measured.status,
            "search_work": measured.work[0],
            "independent_work": measured.work[1],
            "value": None if measured.certificate is None else str(measured.certificate.value),
            "budget16": solve_mix(game, work_limit=16).status,
        }
    return result
