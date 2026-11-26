"""A public prefix provides useful information even after current views reconverge."""

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame


def reconverging_game() -> SlotMixGame:
    """An early public availability observation determines the correct later choice."""
    return SlotMixGame(PublicSlotGame(tuple(
        SharedSlotCase(
            (1, signal, 1, 1),
            (
                SharedAction("start", 0, (0,)),
                SharedAction("a", 3, (2, 3) if signal == 0 else (2,)),
                SharedAction("b", 3, (2, 3) if signal == 1 else (2,)),
            ),
        ) for signal in (0, 1)
    )))
