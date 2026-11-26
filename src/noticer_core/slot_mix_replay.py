"""Check each claimed deterministic policy without frontier construction."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_policy_check import observed
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import Choice


def replay_choice(tape: SharedSlotCase, root: Choice) -> tuple[bool, tuple[Choice, ...]]:
    """A legal policy can fail but may not omit an observable continuation."""
    pending = {item.name: item.deadline for item in tape.actions}
    path: list[Choice] = []
    current = root
    for slot in range(len(tape.capacities)):
        capacity, eligible = observed(tape, slot)
        if (
            type(current) is not Choice
            or current.view != (capacity, eligible)
            or type(current.send) is not tuple
            or any(type(name) is not str for name in current.send)
            or current.send != tuple(sorted(set(current.send)))
            or len(current.send) > capacity
            or not set(current.send) <= (pending.keys() & set(eligible))
            or type(current.children) is not tuple
            or any(type(child) is not Choice for child in current.children)
        ):
            raise ValueError("invalid policy decision")
        path.append(current)
        for name in current.send:
            del pending[name]
        if not pending or any(deadline == slot for deadline in pending.values()):
            if current.children:
                raise ValueError("terminal decision has children")
            return not pending, tuple(path)
        next_view = observed(tape, slot + 1)
        matches = [child for child in current.children if child.view == next_view]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous public continuation")
        current = matches[0]
    raise ValueError("unreachable policy terminal")


def replay_mask(game: SlotMixGame, root: Choice) -> int:
    """Reject any child that cannot be reached on one of the admitted tapes."""
    mask = 0
    reached: dict[int, tuple[Choice, set[int]]] = {}
    for tape_id, tape in enumerate(game.public.tapes):
        success, path = replay_choice(tape, root)
        if success:
            mask |= 1 << tape_id
        for parent, child in zip(path[:-1], path[1:], strict=True):
            reached.setdefault(id(parent), (parent, set()))[1].add(id(child))
    if any(len(children) != len(parent.children) for parent, children in reached.values()):
        raise ValueError("unreachable public continuation")
    return mask
