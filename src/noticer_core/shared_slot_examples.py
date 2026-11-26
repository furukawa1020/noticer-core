"""Small synthetic public cases with intentionally different conclusions."""

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def deadline_gap_case() -> SharedSlotCase:
    """Earlier deadline consumes the only early shared opportunity for B/C."""
    return SharedSlotCase(
        (1, 1, 1),
        (
            SharedAction("a", 1, (0, 1)),
            SharedAction("b", 2, (0, 2)),
            SharedAction("c", 2, (0, 2)),
        ),
    )


def capacity_deficit_case() -> SharedSlotCase:
    """There is global spare capacity, but the two receivers cannot use it."""
    return SharedSlotCase(
        (1, 0, 3),
        (SharedAction("a", 1, (0, 1)), SharedAction("b", 1, (0, 1))),
    )


def no_contention_case() -> SharedSlotCase:
    """A negative control: exact matching must not manufacture a benefit."""
    return SharedSlotCase(
        (1, 1), (SharedAction("a", 0, (0,)), SharedAction("b", 1, (1,)))
    )
