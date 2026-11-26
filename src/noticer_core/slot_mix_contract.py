"""Finite deadline-success game against a tape fixed before the private draw."""

from dataclasses import dataclass

from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_observations import public_observation


@dataclass(frozen=True)
class SlotMixGame:
    """The policy sees observations, never the realized tape's index."""

    public: PublicSlotGame

    def __post_init__(self) -> None:
        if type(self.public) is not PublicSlotGame:
            raise ValueError("expected a bounded public slot game")
        signatures = {
            tuple(public_observation(tape, slot) for slot in range(self.public.horizon))
            for tape in self.public.tapes
        }
        if len(signatures) != len(self.public.tapes):
            raise ValueError("duplicate public tapes must not bias the comparison")
