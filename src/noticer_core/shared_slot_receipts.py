"""Defensive audit of decoded receipt traces in one fixed public context."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_verify import Placement, verify_assignment
from noticer_core.shared_slot_views import PublicReceipt


def receipts_for_assignment(
    case: SharedSlotCase,
    placements: tuple[Placement, ...],
    receivers: dict[str, str],
) -> tuple[PublicReceipt, ...]:
    """Return a canonical trace after checking all authorized actions and receivers."""
    if not verify_assignment(case, placements) or receivers.keys() != {
        action.name for action in case.actions
    }:
        raise ValueError("incomplete or inconsistent public context")
    return tuple(
        PublicReceipt(slot, receivers[name], name) for name, slot in sorted(
            placements, key=lambda placement: (placement[1], placement[0])
        )
    )


def same_joint_receipts(
    case: SharedSlotCase,
    left: tuple[Placement, ...],
    right: tuple[Placement, ...],
    receivers: dict[str, str],
) -> bool:
    """Same action IDs alone do not imply the same decoded receiving trace."""
    return receipts_for_assignment(case, left, receivers) == receipts_for_assignment(
        case, right, receivers
    )
