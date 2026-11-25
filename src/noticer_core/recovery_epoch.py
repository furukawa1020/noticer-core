"""Bind application receipts to a declared public epoch without silent carryover."""

from dataclasses import dataclass

from noticer_core.recovery_delivery import DeliveryPhase, DeliveryState


@dataclass(frozen=True, slots=True)
class PublicEpochDelivery:
    epoch: int
    state: DeliveryState

    def receive(self, epoch: int, authenticated_action: str) -> tuple["PublicEpochDelivery", bool]:
        if type(epoch) is not int or epoch != self.epoch:
            raise ValueError("receipt epoch does not match the active public epoch")
        state, commit = self.state.receive(authenticated_action)
        return PublicEpochDelivery(self.epoch, state), commit

    def begin_next(self, epoch: int, next_action: str) -> "PublicEpochDelivery":
        """An outstanding obligation needs an explicit recovery policy, not a reset."""
        if type(epoch) is not int or epoch != self.epoch + 1 or not next_action:
            raise ValueError("public epoch must advance by exactly one with a declared action")
        if self.state.phase is DeliveryPhase.AWAITING_RECEIPT:
            raise ValueError("uncommitted receipt needs explicit recovery before epoch transition")
        return PublicEpochDelivery(epoch, DeliveryState(next_action))
