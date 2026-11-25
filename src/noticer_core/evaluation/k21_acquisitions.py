"""Determine eligibility from confirmed collection groups, not window counts."""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RecordingEntry:
    participant: str
    acquisition: str
    boundary_confirmed: bool


@dataclass(frozen=True, slots=True)
class Eligibility:
    participants: int
    confirmed_acquisitions: int
    unconfirmed_acquisitions: int
    eligible_participants: int

    @property
    def eligible(self) -> bool:
        return self.participants >= 2 and self.eligible_participants == self.participants


def assess_acquisition_eligibility(
    entries: Iterable[RecordingEntry], *, minimum_per_participant: int
) -> Eligibility:
    """Repeated exports of a single acquisition contribute only one confirmed unit."""
    if type(minimum_per_participant) is not int or minimum_per_participant < 1:
        raise ValueError("minimum acquisitions must be a positive integer")
    boundaries: dict[str, tuple[str, bool]] = {}
    participants: dict[str, int] = defaultdict(int)
    for item in entries:
        if (
            not item.participant
            or not item.acquisition
            or type(item.boundary_confirmed) is not bool
        ):
            raise ValueError("each recording needs owner, acquisition and confirmation state")
        choice = (item.participant, item.boundary_confirmed)
        if item.acquisition in boundaries:
            if boundaries[item.acquisition] != choice:
                raise ValueError("the same acquisition has conflicting ownership or provenance")
        else:
            boundaries[item.acquisition] = choice
            participants[item.participant] += int(item.boundary_confirmed)
    confirmed = sum(participants.values())
    return Eligibility(
        len(participants), confirmed, len(boundaries) - confirmed,
        sum(count >= minimum_per_participant for count in participants.values()),
    )
