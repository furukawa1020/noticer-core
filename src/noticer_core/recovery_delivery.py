"""Reference application state for exactly-once effects after receipt validation."""

from dataclasses import dataclass, replace
from enum import StrEnum


class DeliveryPhase(StrEnum):
    PENDING = "pending"
    AWAITING_RECEIPT = "awaiting-receipt"
    COMMITTED = "committed"


@dataclass(frozen=True, slots=True)
class DeliveryState:
    action: str
    phase: DeliveryPhase = DeliveryPhase.PENDING
    attempts: int = 0

    def send(self) -> "DeliveryState":
        """Record a logical attempt without committing the action."""
        if not self.action or self.phase is DeliveryPhase.COMMITTED:
            raise ValueError("empty or already committed action")
        return replace(self, phase=DeliveryPhase.AWAITING_RECEIPT, attempts=self.attempts + 1)

    def receive(self, validated_action: str) -> tuple["DeliveryState", bool]:
        """Return whether to commit the effect; receipt authentication is upstream."""
        if validated_action != self.action or self.phase is DeliveryPhase.PENDING:
            raise ValueError("receipt for an unsent or different action")
        if self.phase is DeliveryPhase.COMMITTED:
            return self, False
        return replace(self, phase=DeliveryPhase.COMMITTED), True
