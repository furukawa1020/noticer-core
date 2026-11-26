"""Project fixed public receiver availability and immutable deadlines."""

from dataclasses import dataclass

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


@dataclass(frozen=True)
class PublicDemand:
    """A public unit action for a named receiver, all released before slot zero."""

    action: str
    receiver: str
    deadline: int


def project_public_tape(
    capacities: tuple[int, ...],
    available: tuple[frozenset[str], ...],
    demands: tuple[PublicDemand, ...],
) -> SharedSlotCase:
    """A receiver omitted in a slot cannot accept any action in that slot."""
    if type(available) is not tuple or len(available) != len(capacities):
        raise ValueError("availability horizon does not match capacity")
    if any(
        type(receivers) is not frozenset or any(type(name) is not str for name in receivers)
        for receivers in available
    ):
        raise ValueError("invalid public availability")
    if type(demands) is not tuple or any(
        type(demand) is not PublicDemand
        or type(demand.receiver) is not str
        or not demand.receiver
        or type(demand.deadline) is not int
        for demand in demands
    ):
        raise ValueError("invalid demand")
    return SharedSlotCase(
        capacities,
        tuple(
            SharedAction(
                demand.action,
                demand.deadline,
                tuple(
                    slot
                    for slot, receivers in enumerate(available)
                    if slot <= demand.deadline and demand.receiver in receivers
                ),
            )
            for demand in demands
        ),
    )
