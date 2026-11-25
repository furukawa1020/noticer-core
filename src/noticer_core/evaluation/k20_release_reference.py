"""Reference release schedules for K20 metadata and overhead comparisons.

These models do not encrypt, authenticate, or send data. On-wire encryption
overhead is supplied by the experiment contract.
"""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReleaseRequest:
    action_id: str
    ready_slot: int
    deadline_slot: int
    body_bytes: int


@dataclass(frozen=True, slots=True)
class ObservedFrame:
    slot: int
    wire_bytes: int


@dataclass(frozen=True, slots=True)
class ReleaseSimulation:
    frames: tuple[ObservedFrame, ...]
    deliveries: tuple[tuple[str, int], ...]
    undelivered: tuple[str, ...]


def release_inputs(
    requests: Iterable[ReleaseRequest], *, horizon: int, crypto_bytes: int
) -> tuple[ReleaseRequest, ...]:
    """Validate a bounded slot horizon and sort offers in a canonical order."""
    if type(horizon) is not int or not 1 <= horizon <= 100_000:
        raise ValueError("horizon must be an integer in [1, 100000]")
    if type(crypto_bytes) is not int or crypto_bytes < 1:
        raise ValueError("crypto byte overhead must be a positive integer")
    seen: set[str] = set()
    ordered: list[ReleaseRequest] = []
    for item in requests:
        if not item.action_id or item.action_id in seen:
            raise ValueError("each release request needs a unique action identifier")
        seen.add(item.action_id)
        if any(type(value) is not int
               for value in (item.ready_slot, item.deadline_slot, item.body_bytes)):
            raise ValueError("slot and byte fields must be integers")
        if not 0 <= item.ready_slot < horizon or item.deadline_slot < item.ready_slot:
            raise ValueError("invalid release slot or deadline")
        if item.body_bytes < 1 or len(seen) > 100_000:
            raise ValueError("requests require positive byte sizes and a bounded count")
        ordered.append(item)
    return tuple(sorted(ordered, key=lambda item: (item.ready_slot, item.action_id)))


def simulate_encryption_only(
    requests: Iterable[ReleaseRequest], *, horizon: int, crypto_bytes: int
) -> ReleaseSimulation:
    """Model encrypted frame lengths without padding, delay, or cover frames."""
    ordered = release_inputs(requests, horizon=horizon, crypto_bytes=crypto_bytes)
    return ReleaseSimulation(
        tuple(ObservedFrame(item.ready_slot, item.body_bytes + crypto_bytes) for item in ordered),
        tuple((item.action_id, item.ready_slot) for item in ordered),
        (),
    )
