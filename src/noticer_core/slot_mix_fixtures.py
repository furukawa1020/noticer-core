"""Two-slot examples whose tape rows name possible last-slot actions."""

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame


def last_slot_game(actions: int, row_masks: tuple[int, ...]) -> SlotMixGame:
    """Send all but one action before the future is revealed; finish in slot 1."""
    if type(actions) is not int or not 2 <= actions <= 8 or any(
        type(row) is not int or not 0 <= row < (1 << actions) for row in row_masks
    ):
        raise ValueError("invalid last-slot incidence")
    tapes = tuple(
        SharedSlotCase(
            (actions - 1, 1),
            tuple(
                SharedAction(f"a{i}", 1, (0, 1) if mask & (1 << i) else (0,))
                for i in range(actions)
            ),
        )
        for mask in row_masks
    )
    return SlotMixGame(PublicSlotGame(tapes))


def asymmetric_game() -> SlotMixGame:
    """A pairwise-overlap triangle plus a tape requiring its own reserve."""
    return last_slot_game(4, (0b0011, 0b0101, 0b0110, 0b1000))
