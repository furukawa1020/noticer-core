"""Portable public game data; proof weights cannot change its interpretation."""

from dataclasses import asdict
from typing import Any

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_json import exact_members


def encode_tapes(game: SlotMixGame) -> list[dict[str, Any]]:
    """Export public tapes without host or private metadata."""
    return [asdict(tape) for tape in game.public.tapes]


def decode_tapes(raw: Any) -> SlotMixGame:
    """Validate parsed arrays before constructing the input contract."""
    if type(raw) is not list or not 1 <= len(raw) <= 8:
        raise ValueError("invalid public tapes")
    tapes = []
    for item in raw:
        item = exact_members(item, {"capacities", "actions"})
        capacities, actions = item["capacities"], item["actions"]
        if (
            type(capacities) is not list or not 1 <= len(capacities) <= 8
            or type(actions) is not list or len(actions) > 8
        ):
            raise ValueError("invalid public game dimensions")
        demands = []
        for action in actions:
            action = exact_members(action, {"name", "deadline", "slots"})
            slots = action["slots"]
            if type(slots) is not list or len(slots) > 8:
                raise ValueError("invalid public eligibility")
            demands.append(SharedAction(action["name"], action["deadline"], tuple(slots)))
        tapes.append(SharedSlotCase(tuple(capacities), tuple(demands)))
    return SlotMixGame(PublicSlotGame(tuple(tapes)))
