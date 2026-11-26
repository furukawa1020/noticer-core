"""Observer projections for fixed public control and decoded receipt events."""

from dataclasses import dataclass
from typing import Literal

Observer = Literal["service", "coalition", "network"]


@dataclass(frozen=True)
class PublicReceipt:
    """One visible application delivery; slot is logical, not wall time."""

    slot: int
    receiver: str
    action: str


@dataclass(frozen=True)
class TraceView:
    """Only the fields available to the explicitly selected observer."""

    receipts: tuple[PublicReceipt, ...]
    reservation: tuple[int, ...] | None


def project_trace(
    receipts: tuple[PublicReceipt, ...],
    reservation: tuple[int, ...],
    observer: Observer,
    *,
    receiver: str | None = None,
    reservation_public: bool = False,
) -> TraceView:
    """Do not conflate a decoded service view with scheduled frame counts."""
    if observer not in ("service", "coalition", "network"):
        raise ValueError("unknown observer")
    if (observer == "service") != (receiver is not None):
        raise ValueError("only a service view requires exactly one receiver")
    visible = (
        tuple(receipt for receipt in receipts if receipt.receiver == receiver)
        if observer == "service"
        else receipts if observer == "coalition" else ()
    )
    return TraceView(visible, reservation if observer == "network" or reservation_public else None)
