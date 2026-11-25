"""Explicit wire byte accounting for matched mechanism comparisons."""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WireEvent:
    payload_bytes: int
    padding_bytes: int
    protocol_bytes: int
    retransmission: bool = False


@dataclass(frozen=True, slots=True)
class WireCost:
    events: int
    wire_bytes: int
    payload_bytes: int
    padding_bytes: int
    protocol_bytes: int
    retransmitted_bytes: int

    @property
    def padding_fraction(self) -> float | None:
        """Fraction of all observed wire bytes, including retransmissions."""
        return self.padding_bytes / self.wire_bytes if self.wire_bytes else None


def summarize_wire_cost(events: Iterable[WireEvent]) -> WireCost:
    """Count every actual wire event exactly once, including retry or cover events."""
    count = payload = padding = protocol = retries = 0
    for event in events:
        components = (event.payload_bytes, event.padding_bytes, event.protocol_bytes)
        if any(type(value) is not int or value < 0 for value in components):
            raise ValueError("wire sizes must be nonnegative integer byte counts")
        if type(event.retransmission) is not bool or not any(components):
            raise ValueError("a wire event requires bytes and an explicit retransmission marker")
        count += 1
        payload += event.payload_bytes
        padding += event.padding_bytes
        protocol += event.protocol_bytes
        if event.retransmission:
            retries += sum(components)
    return WireCost(count, payload + padding + protocol, payload, padding, protocol, retries)
