"""Classify a decision after applying only its legal completed sends."""

from typing import Literal

from noticer_core.shared_slot_moves import Move

Terminal = Literal["complete", "expired", "continue"]


def delivery_status(pending: Move, deadlines: dict[str, int], slot: int) -> Terminal:
    """Incomplete actions whose inclusive deadline was reached are a loss."""
    if not pending:
        return "complete"
    if any(deadlines[action] <= slot for action in pending):
        return "expired"
    return "continue"
