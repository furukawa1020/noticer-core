"""Only an observable prefix can refine the current information set."""

from dataclasses import dataclass

from noticer_core.shared_slot_observations import Observation, refine_tapes
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_masks import tape_mask


@dataclass(frozen=True)
class PublicBelief:
    """An internal group behind one observed capacity and eligibility value."""

    slot: int
    view: Observation
    indices: tuple[int, ...]

    @property
    def mask(self) -> int:
        """The worlds sharing this public prefix."""
        return tape_mask(self.indices)


def initial_belief(game: SlotMixGame) -> PublicBelief:
    """Use the common declared first observation."""
    (view, group), = refine_tapes(game.public, tuple(range(len(game.public.tapes))), 0)
    return PublicBelief(0, view, group)


def successors(game: SlotMixGame, belief: PublicBelief) -> tuple[PublicBelief, ...]:
    """Discard incompatible pasts rather than partitioning globally at each step."""
    slot = belief.slot + 1
    if slot >= game.public.horizon:
        return ()
    return tuple(
        PublicBelief(slot, view, ids)
        for view, ids in refine_tapes(game.public, belief.indices, slot)
    )
