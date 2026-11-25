"""Independent check of a public one-lane delivery assignment."""

from collections.abc import Sequence

from noticer_core.recovery_capacity import CapacityResult, PublicRequest


def check_capacity_assignment(
    requests: Sequence[PublicRequest], available: tuple[bool, ...], result: CapacityResult
) -> None:
    """Check safety and completeness of the inventory, not optimality of scheduling."""
    obligations = {request.service: request for request in requests}
    if len(obligations) != len(requests):
        raise ValueError("duplicate request")
    delivered: set[str] = set()
    slots: set[int] = set()
    for event in result.delivered:
        required = obligations.get(event.service)
        if required is None or event.service in delivered:
            raise ValueError("unauthorized or repeated delivery")
        if type(event.slot) is not int or not 0 <= event.slot < len(available):
            raise ValueError("delivery outside the public tape")
        if event.slot in slots or not available[event.slot]:
            raise ValueError("delivery violates lane capacity or availability")
        if not required.first_slot <= event.slot <= required.deadline:
            raise ValueError("delivery violates the service deadline")
        delivered.add(event.service)
        slots.add(event.slot)
    if result.deadline_misses != tuple(sorted(obligations.keys() - delivered)):
        raise ValueError("declared misses do not match the remaining obligations")
