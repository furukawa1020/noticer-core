"""A public handoff of capacity across differently constrained receivers."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_public import PublicDemand, project_public_tape


def handoff_case() -> SharedSlotCase:
    """An early singleton can move one frame to the handoff slot; B cannot."""
    avail = (
        frozenset({"carry", "dropout"}),
        frozenset({"carry"}),
        frozenset({"dropout"}),
    )
    return project_public_tape(
        (2, 1, 1),
        avail,
        (
            PublicDemand("early", "carry", 1),
            PublicDemand("b1", "dropout", 2),
            PublicDemand("b2", "dropout", 2),
            PublicDemand("b3", "dropout", 2),
        ),
    )
