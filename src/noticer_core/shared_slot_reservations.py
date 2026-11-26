"""Tie public reservation counts to authorized unit actions."""

from collections import Counter

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_verify import Placement, verify_assignment


def reservation_counts(
    case: SharedSlotCase, placements: tuple[Placement, ...]
) -> tuple[int, ...]:
    """Require a complete assignment before a count shape is evidence."""
    if not verify_assignment(case, placements):
        raise ValueError("reservation requires a complete authorized assignment")
    selected = Counter(slot for _, slot in placements)
    return tuple(selected.get(slot, 0) for slot in range(len(case.capacities)))


def verify_reservation_shape(
    case: SharedSlotCase, placements: tuple[Placement, ...], shape: tuple[int, ...]
) -> bool:
    """Check embedding within per-slot capacity; unfilled positions may pad."""
    if len(shape) != len(case.capacities) or not verify_assignment(case, placements):
        return False
    counts = reservation_counts(case, placements)
    return all(
        type(frame_count) is int and used <= frame_count <= capacity
        for used, frame_count, capacity in zip(counts, shape, case.capacities, strict=True)
    )
