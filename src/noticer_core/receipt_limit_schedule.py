"""Validate delivered-only schedules, including deliberate withholding."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_verify import Placement, verify_assignment

Schedule = tuple[Placement, ...]


def schedule_success(world: SharedSlotCase, schedule: Schedule) -> bool:
    """Do not turn an impossible or malformed plan into an ordinary failure."""
    if not verify_assignment(world, schedule, complete=False) or schedule != tuple(
        sorted(schedule)
    ):
        raise ValueError("invalid schedule")
    return len(schedule) == len(world.actions)
