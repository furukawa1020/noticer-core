"""Bounded input codec for private eligibility choices in public fixtures."""

from typing import Any

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.slot_mix_json import exact_members


def decode_histories(raw: Any, recipients: Any) -> ReceiptProblem:
    """Validate arrays before declaring the public contract equivalent."""
    if type(raw) is not list or len(raw) != 2:
        raise ValueError("invalid history list")
    if type(recipients) is not list or len(recipients) > 5 or any(
        type(pair) is not list or len(pair) != 2 for pair in recipients
    ):
        raise ValueError("invalid public receiver map")
    worlds = []
    for item in raw:
        item = exact_members(item, {"capacities", "actions"})
        capacities, actions = item["capacities"], item["actions"]
        if type(capacities) is not list or not 1 <= len(capacities) <= 5:
            raise ValueError("invalid logical capacity")
        if type(actions) is not list or len(actions) > 5:
            raise ValueError("invalid action catalog")
        demands = []
        for raw_action in actions:
            action = exact_members(raw_action, {"name", "deadline", "slots"})
            slots = action["slots"]
            if type(slots) is not list or len(slots) > 5:
                raise ValueError("invalid eligibility")
            demands.append(SharedAction(action["name"], action["deadline"], tuple(slots)))
        worlds.append(SharedSlotCase(tuple(capacities), tuple(demands)))
    return ReceiptProblem((worlds[0], worlds[1]), tuple(tuple(pair) for pair in recipients))
