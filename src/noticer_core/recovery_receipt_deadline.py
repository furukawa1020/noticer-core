"""Explicit receipt deadline for the abstract recovery effects contract."""

from dataclasses import dataclass, replace

from noticer_core.recovery_delivery import DeliveryState


@dataclass(frozen=True, slots=True)
class ReceiptWindow:
    state: DeliveryState
    first_slot: int
    deadline: int

    def receive(self, slot: int, validated_action: str) -> tuple["ReceiptWindow", bool]:
        """Even authenticated receipts must fit the frozen public execution window."""
        if any(type(value) is not int for value in (slot, self.first_slot, self.deadline)):
            raise ValueError("receipt and deadline slots must be integers")
        if not 0 <= self.first_slot <= slot <= self.deadline:
            raise ValueError("receipt outside the authorized execution window")
        updated, commit = self.state.receive(validated_action)
        return replace(self, state=updated), commit
