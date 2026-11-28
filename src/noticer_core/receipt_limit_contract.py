"""Bounded two-history receipt model, not an actual transport protocol."""

from dataclasses import dataclass

from noticer_core.shared_slot_contract import SharedSlotCase


@dataclass(frozen=True)
class ReceiptProblem:
    """Public capacity, action/deadline/recipient map; private eligible slots."""

    worlds: tuple[SharedSlotCase, SharedSlotCase]
    recipients: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if type(self.worlds) is not tuple or len(self.worlds) != 2 or any(
            type(world) is not SharedSlotCase for world in self.worlds
        ):
            raise ValueError("expected two histories")
        left, right = self.worlds
        if len(left.capacities) > 5 or len(left.actions) > 5:
            raise ValueError("receipt game exceeds finite limit")
        def public(world: SharedSlotCase) -> tuple[tuple[str, int], ...]:
            return tuple(sorted((a.name, a.deadline) for a in world.actions))

        if left.capacities != right.capacities or public(left) != public(right):
            raise ValueError("histories must agree on all public commitments")
        if (
            type(self.recipients) is not tuple
            or any(
                type(pair) is not tuple or len(pair) != 2
                or any(type(name) is not str or not name or len(name) > 64 for name in pair)
                for pair in self.recipients
            )
            or tuple(name for name, _ in self.recipients) != tuple(name for name, _ in public(left))
        ):
            raise ValueError("recipient map must cover ordered public actions")
