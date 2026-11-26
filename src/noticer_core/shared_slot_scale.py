"""Deterministic sparse/dense cases for varying one scaling axis at a time."""

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def scaling_cases() -> tuple[tuple[str, SharedSlotCase], ...]:
    """Vary action count, horizon, or outages without mixing the labels."""
    rows = []
    for size in (8, 16, 32, 48):
        case = SharedSlotCase(
            (3,) * 16, tuple(SharedAction(f"a{i}", 15, tuple(range(16))) for i in range(size))
        )
        rows.append((f"actions-{size}", case))
    for horizon in (8, 16, 32, 64):
        case = SharedSlotCase(
            (2,) * horizon,
            tuple(SharedAction(f"a{i}", horizon - 1, tuple(range(horizon))) for i in range(16)),
        )
        rows.append((f"horizon-{horizon}", case))
    for outages in (0, 2, 4, 8):
        case = SharedSlotCase(
            (0,) * outages + (2,) * (16 - outages),
            tuple(SharedAction(f"a{i}", 15, tuple(range(16))) for i in range(24)),
        )
        rows.append((f"outage-{outages}", case))
    return tuple(rows)
