"""Canonical public observations and fixed-tape prefix refinement."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame

Observation = tuple[int, tuple[str, ...]]


def public_observation(tape: SharedSlotCase, slot: int) -> Observation:
    """Capacity and those authorized actions currently able to use it."""
    return tape.capacities[slot], tuple(
        sorted(action.name for action in tape.actions if slot in action.slots)
    )


def refine_tapes(
    game: PublicSlotGame, tapes: tuple[int, ...], slot: int
) -> tuple[tuple[Observation, tuple[int, ...]], ...]:
    """Split compatible worlds by the next public input, not by hidden tape ID."""
    groups: dict[Observation, list[int]] = {}
    for index in tapes:
        observation = public_observation(game.tapes[index], slot)
        groups.setdefault(observation, []).append(index)
    return tuple((observation, tuple(groups[observation])) for observation in sorted(groups))
