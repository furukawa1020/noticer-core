"""Canonical joint recipient logs with explicit tie and sequence rules."""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RecipientEvent:
    service: str
    slot: int
    sequence: int
    event: str


def assemble_coalition(
    allowed: tuple[str, ...], events: Iterable[RecipientEvent]
) -> tuple[RecipientEvent, ...]:
    """Scalar order: logical slot, recipient label, then per-recipient sequence."""
    if not allowed or len(set(allowed)) != len(allowed) or "" in allowed:
        raise ValueError("the coalition must name distinct recipients")
    grouped: dict[str, dict[int, RecipientEvent]] = {service: {} for service in allowed}
    for item in events:
        if item.service not in grouped or not item.event:
            raise ValueError("the event is outside the declared recipient projection")
        if type(item.slot) is not int or type(item.sequence) is not int:
            raise ValueError("slots and sequences must be integers")
        lane = grouped[item.service]
        if item.slot < 0 or item.sequence < 0 or item.sequence in lane:
            raise ValueError("negative slot or repeated recipient sequence")
        lane[item.sequence] = item
    for lane in grouped.values():
        ordered = sorted(lane)
        if ordered != list(range(len(ordered))):
            raise ValueError("recipient sequence is incomplete")
        if any(lane[a].slot > lane[b].slot for a, b in zip(ordered, ordered[1:], strict=False)):
            raise ValueError("recipient sequence and slot order disagree")
    return tuple(sorted(
        (event for lane in grouped.values() for event in lane.values()),
        key=lambda event: (event.slot, event.service, event.sequence),
    ))
