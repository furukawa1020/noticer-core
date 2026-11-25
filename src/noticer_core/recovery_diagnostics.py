"""A closed public diagnostic projection, without internal error strings."""

from enum import StrEnum


class AvailabilityClass(StrEnum):
    AVAILABLE = "available"
    PUBLIC_OUTAGE = "public-outage"
    NOT_ESTABLISHED = "not-established"


class PublicDiagnostic(StrEnum):
    ACCEPTED = "accepted"
    DEFERRED = "deferred"
    UNAVAILABLE = "unavailable"


def public_diagnostic(availability: AvailabilityClass) -> PublicDiagnostic:
    """The projection accepts only public availability, not detailed internal failures."""
    if not isinstance(availability, AvailabilityClass):
        raise ValueError("only declared public availability can be projected")
    return {
        AvailabilityClass.AVAILABLE: PublicDiagnostic.ACCEPTED,
        AvailabilityClass.PUBLIC_OUTAGE: PublicDiagnostic.DEFERRED,
        AvailabilityClass.NOT_ESTABLISHED: PublicDiagnostic.UNAVAILABLE,
    }[availability]
