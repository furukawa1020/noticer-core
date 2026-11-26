"""Small public uncertainty controls which differ after slot zero."""

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame


def robust_schedule_game() -> PublicSlotGame:
    """A public policy can hedge by sending B before the future is observed."""
    a = SharedAction("a", 1, (0, 1))
    c = SharedAction("c", 2, (0, 2))
    return PublicSlotGame(
        (
            SharedSlotCase(
                (1, 1, 1), (a, SharedAction("b", 2, (0, 2)), SharedAction("c", 2, (0, 1, 2)))
            ),
            SharedSlotCase((1, 1, 1), (a, SharedAction("b", 2, (0,)), c)),
        )
    )


def late_conflict_game() -> PublicSlotGame:
    """Both futures allow the same first move, but conflict at slot one."""
    start = SharedAction("start", 0, (0,))
    return PublicSlotGame(
        (
            SharedSlotCase(
                (1, 1, 1), (start, SharedAction("a", 2, (1, 2)), SharedAction("b", 2, (1,)))
            ),
            SharedSlotCase(
                (1, 1, 1), (start, SharedAction("a", 2, (1,)), SharedAction("b", 2, (1, 2)))
            ),
        )
    )
