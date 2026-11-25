"""Finite reference for unit-frame requests sharing one public transmission lane."""

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PublicRequest:
    service: str
    first_slot: int
    deadline: int


@dataclass(frozen=True, slots=True)
class PublicDelivery:
    service: str
    slot: int


@dataclass(frozen=True, slots=True)
class CapacityResult:
    delivered: tuple[PublicDelivery, ...]
    deadline_misses: tuple[str, ...]


def schedule_shared_lane(
    requests: Sequence[PublicRequest], availability: tuple[bool, ...]
) -> CapacityResult:
    """Serve at most one unit frame per available slot, in earliest-deadline order."""
    if not availability or any(type(slot) is not bool for slot in availability):
        raise ValueError("availability must explicitly describe a finite public tape")
    if len({item.service for item in requests}) != len(requests):
        raise ValueError("only one authorized action per service is supported")
    for item in requests:
        if (
            not item.service
            or type(item.first_slot) is not int
            or type(item.deadline) is not int
            or not 0 <= item.first_slot <= item.deadline < len(availability)
        ):
            raise ValueError("request has an invalid public deadline")
    pending = sorted(requests, key=lambda item: (item.deadline, item.service))
    delivered = []
    for slot, available in enumerate(availability):
        if not available:
            continue
        choice = next((item for item in pending if item.first_slot <= slot <= item.deadline), None)
        if choice is not None:
            pending.remove(choice)
            delivered.append(PublicDelivery(choice.service, slot))
    return CapacityResult(tuple(delivered), tuple(sorted(item.service for item in pending)))
