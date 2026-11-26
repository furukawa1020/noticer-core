"""Independently check that a finite loss certificate covers every legal move."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_policy_check import observed
from noticer_core.shared_slot_strategy import MAX_GAME_MOVES, LossNode


def verify_game_loss(game: PublicSlotGame, proof: LossNode) -> bool:
    """Recompute the powerset and the observed branch groups from raw tapes."""
    remaining_checks = MAX_GAME_MOVES
    deadlines = game.deadlines

    def verify(
        node: LossNode,
        slot: int,
        group: tuple[SharedSlotCase, ...],
        pending: tuple[str, ...],
    ) -> bool:
        nonlocal remaining_checks
        capacity, eligible = observed(group[0], slot)
        if (
            (node.slot, node.observation, node.pending) != (slot, (capacity, eligible), pending)
            or any(observed(tape, slot) != (capacity, eligible) for tape in group)
        ):
            return False
        allowed = tuple(name for name in pending if name in eligible)
        legal = {
            tuple(name for index, name in enumerate(allowed) if bits & (1 << index))
            for bits in range(1 << len(allowed))
            if bits.bit_count() <= capacity
        }
        sent = {entry.send for entry in node.rejected}
        if sent != legal or len(node.rejected) != len(legal):
            return False
        for entry in node.rejected:
            if remaining_checks == 0:
                return False
            remaining_checks -= 1
            rest = tuple(name for name in pending if name not in entry.send)
            expired = tuple(name for name in rest if deadlines[name] <= slot)
            if entry.expired != expired:
                return False
            if expired:
                if entry.child is not None:
                    return False
                continue
            if entry.child is None or not rest or slot + 1 >= game.horizon:
                return False
            next_group = tuple(
                tape for tape in group if observed(tape, slot + 1) == entry.child.observation
            )
            if not next_group or not verify(entry.child, slot + 1, next_group, rest):
                return False
        return True

    return verify(proof, 0, game.tapes, tuple(deadlines))
