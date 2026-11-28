"""Counterparts with the same authorization, differing only in ready slots."""

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def crossed_recipients(
    first: tuple[int, ...] = (1,), second: tuple[int, ...] = (0,)
) -> ReceiptProblem:
    """A can go anywhere; receiver B's action has history-specific eligibility."""
    flexible = SharedAction("a", 1, (0, 1))
    return ReceiptProblem(
        (
            SharedSlotCase((1, 1), (flexible, SharedAction("b", 1, first))),
            SharedSlotCase((1, 1), (flexible, SharedAction("b", 1, second))),
        ),
        (("a", "receiver-a"), ("b", "receiver-b")),
    )
