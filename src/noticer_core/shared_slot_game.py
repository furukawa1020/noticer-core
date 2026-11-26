"""Bounded public uncertainty class for a common-prefix release contract."""

from dataclasses import dataclass

from noticer_core.shared_slot_contract import SharedSlotCase

MAX_GAME_HORIZON = 8
MAX_GAME_ACTIONS = 8
MAX_GAME_TAPES = 8


@dataclass(frozen=True)
class PublicSlotGame:
    """One fixed future tape is realized; only the current prefix is observed."""

    tapes: tuple[SharedSlotCase, ...]

    def __post_init__(self) -> None:
        if type(self.tapes) is not tuple or not 1 <= len(self.tapes) <= MAX_GAME_TAPES:
            raise ValueError("invalid number of public tapes")
        if any(type(tape) is not SharedSlotCase for tape in self.tapes):
            raise ValueError("invalid public tape")
        first = self.tapes[0]
        if len(first.actions) > MAX_GAME_ACTIONS or len(first.capacities) > MAX_GAME_HORIZON:
            raise ValueError("public game exceeds action or horizon bound")
        if any(
            len(tape.capacities) != len(first.capacities)
            or public_demand(tape) != public_demand(first)
            or tape.capacities[0] != first.capacities[0]
            or _eligible_at_zero(tape) != _eligible_at_zero(first)
            for tape in self.tapes[1:]
        ):
            raise ValueError("game must share demand, horizon, and its first public view")

    @property
    def deadlines(self) -> dict[str, int]:
        """The same immutable public deadline promises apply to every tape."""
        return dict(public_demand(self.tapes[0]))

    @property
    def horizon(self) -> int:
        """The declared common length of all public availability tapes."""
        return len(self.tapes[0].capacities)


def public_demand(tape: SharedSlotCase) -> tuple[tuple[str, int], ...]:
    """Return the canonical immutable action/deadline metadata."""
    return tuple(sorted((action.name, action.deadline) for action in tape.actions))


def _eligible_at_zero(tape: SharedSlotCase) -> set[str]:
    return {action.name for action in tape.actions if 0 in action.slots}
