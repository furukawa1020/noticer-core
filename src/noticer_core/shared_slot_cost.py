"""Do not conflate application frame budget with delivery timing."""

from dataclasses import dataclass
from fractions import Fraction

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_verify import Placement, verify_assignment


@dataclass(frozen=True)
class SharedSlotCost:
    """Unpadded application bytes and delay from the common slot-zero release."""

    delivered: int
    required: int
    application_bytes: int
    mean_logical_slots: Fraction | None


def measure_shared_slot_cost(
    case: SharedSlotCase,
    placements: tuple[Placement, ...],
    application_bytes_per_action: dict[str, int],
) -> SharedSlotCost:
    """Measure valid partial/full assignments; misses remain in the denominator."""
    if not verify_assignment(case, placements, complete=False):
        raise ValueError("invalid allocation")
    if application_bytes_per_action.keys() != {action.name for action in case.actions} or any(
        type(size) is not int or size < 0 for size in application_bytes_per_action.values()
    ):
        raise ValueError("invalid application byte accounting")
    count = len(placements)
    return SharedSlotCost(
        count,
        len(case.actions),
        sum(application_bytes_per_action[name] for name, _ in placements),
        Fraction(sum(slot for _, slot in placements), count) if count else None,
    )
