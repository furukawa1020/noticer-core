"""Bounded, public-window receipt schedules for a defensive finite model.

This is an abstract replay model. Availability is public and supplied in a tape.
No real ACKs, retransmissions, encryption, or network stack are modeled here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ScheduleMode(StrEnum):
    RECIPIENT_ONLY = "recipient-only"
    NETWORK_ENVELOPE = "network-envelope"
    FIXED_RATE = "fixed-rate"
    DEADLINE_WAIT = "deadline-wait"


class OutOfScopeTape(ValueError):
    """A public tape exceeded the declared availability assumptions."""


@dataclass(frozen=True, slots=True)
class ServiceWindow:
    service: str
    not_before: int
    deadline: int
    max_unavailable: int


@dataclass(frozen=True, slots=True)
class Receipt:
    service: str
    slot: int


@dataclass(frozen=True, slots=True)
class WireFrame:
    service: str
    slot: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class Replay:
    receipts: tuple[Receipt, ...]
    frames: tuple[WireFrame, ...]
    cover_frames: int
    missed: tuple[str, ...]

    @property
    def model_bytes(self) -> int:
        return sum(frame.byte_count for frame in self.frames)


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    windows: tuple[ServiceWindow, ...]
    frame_bytes: int

    def replay(
        self,
        admissions: Mapping[str, int],
        availability: Mapping[str, tuple[bool, ...]],
        *,
        mode: ScheduleMode,
    ) -> Replay:
        """Replay admitted actions and return allowlisted receipts and packet shapes.

        A present admission is one synthetic action; missing keys mean no action.
        Private ready slots are checked against the public boundary, then discarded.
        This offline replay rejects out-of-scope tapes before emitting any result.
        """
        if not isinstance(mode, ScheduleMode):
            raise ValueError("unsupported schedule mode")
        known = {window.service for window in self.windows}
        if availability.keys() != known or not admissions.keys() <= known:
            raise ValueError("undeclared service or missing availability lane")

        slots_by_service: dict[str, tuple[int, ...]] = {}
        for window in self.windows:
            lane = availability[window.service]
            if len(lane) != window.deadline - window.not_before + 1 or any(
                type(slot_available) is not bool for slot_available in lane
            ):
                raise ValueError("availability must cover exactly the public window")
            if lane.count(False) > window.max_unavailable:
                raise OutOfScopeTape("public outage budget exceeded")
            slots_by_service[window.service] = tuple(
                slot for slot, enabled in enumerate(lane, start=window.not_before) if enabled
            )
            if window.service in admissions:
                ready = admissions[window.service]
                if type(ready) is not int or not 0 <= ready < window.not_before:
                    raise ValueError("action not admitted before its public window")

        receipts = []
        frames = []
        missed = []
        cover = 0
        for window in self.windows:
            service = window.service
            action = service in admissions
            opportunities = slots_by_service[service]
            if mode is ScheduleMode.DEADLINE_WAIT:
                transmit = (window.deadline,) if action and window.deadline in opportunities else ()
            elif mode is ScheduleMode.FIXED_RATE:
                transmit = opportunities
            elif mode is ScheduleMode.NETWORK_ENVELOPE or action:
                transmit = opportunities[:1]
            else:
                transmit = ()

            frames.extend(WireFrame(service, slot, self.frame_bytes) for slot in transmit)
            if action and transmit:
                receipts.append(Receipt(service, transmit[0]))
                cover += len(transmit) - 1
            else:
                cover += len(transmit)
                if action:
                    missed.append(service)
        return Replay(
            tuple(sorted(receipts, key=lambda item: (item.slot, item.service))),
            tuple(sorted(frames, key=lambda item: (item.slot, item.service))),
            cover,
            tuple(missed),
        )


def compile_public_plan(
    windows: tuple[ServiceWindow, ...], *, frame_bytes: int
) -> RecoveryPlan:
    """Construct the first-available schedule in the one-action-per-lane model."""
    if type(frame_bytes) is not int or frame_bytes <= 0:
        raise ValueError("configured frame length must be positive")
    if not windows or len({window.service for window in windows}) != len(windows):
        raise ValueError("windows must name a nonempty set of distinct services")
    for window in windows:
        lower, upper, outages = window.not_before, window.deadline, window.max_unavailable
        if not window.service or any(type(value) is not int for value in (lower, upper, outages)):
            raise ValueError("a window requires a named service and integer bounds")
        if not 1 <= lower <= upper or not 0 <= outages < upper - lower + 1:
            raise ValueError("each public window must have at least one available opportunity")
    return RecoveryPlan(tuple(sorted(windows, key=lambda item: item.service)), frame_bytes)
