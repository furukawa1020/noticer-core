"""Independent per-tape replay of a public causal policy."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_strategy import PolicyNode
from noticer_core.shared_slot_verify import Placement, verify_assignment


def observed(tape: SharedSlotCase, slot: int) -> tuple[int, tuple[str, ...]]:
    """Compute a replay observation directly from the tape."""
    eligible = [action.name for action in tape.actions if slot in action.slots]
    return tape.capacities[slot], tuple(sorted(eligible))


def replay_policy(
    tape: SharedSlotCase, root: PolicyNode
) -> tuple[tuple[Placement, ...], tuple[PolicyNode, ...]] | None:
    """Check one tape's decisions, using only one child for each next observation."""
    pending = {action.name: action.deadline for action in tape.actions}
    node = root
    path = []
    placements = []
    for slot in range(len(tape.capacities)):
        capacity, eligible = observed(tape, slot)
        if (
            node.slot != slot
            or node.observation != (capacity, eligible)
            or node.pending != tuple(sorted(pending))
            or any(type(name) is not str for name in node.send)
            or tuple(sorted(set(node.send))) != node.send
            or len(node.send) > capacity
            or any(name not in pending or name not in eligible for name in node.send)
        ):
            return None
        path.append(node)
        for name in node.send:
            del pending[name]
            placements.append((name, slot))
        if not pending:
            result = tuple(sorted(placements))
            return (result, tuple(path)) if not node.children and verify_assignment(
                tape, result
            ) else None
        if min(pending.values()) <= slot or slot + 1 == len(tape.capacities):
            return None
        next_observation = observed(tape, slot + 1)
        matches = [child for child in node.children if child.observation == next_observation]
        if len(matches) != 1:
            return None
        node = matches[0]
    return None


def verify_policy(game: PublicSlotGame, policy: PolicyNode) -> bool:
    """Require every admitted tape to pass without unobserved branches."""
    parents: dict[int, tuple[PolicyNode, set[int]]] = {}
    for tape in game.tapes:
        replay = replay_policy(tape, policy)
        if replay is None:
            return False
        _, path = replay
        for parent, child in zip(path[:-1], path[1:], strict=True):
            parents.setdefault(id(parent), (parent, set()))[1].add(id(child))
    return all(len(reached) == len(parent.children) for parent, reached in parents.values())
