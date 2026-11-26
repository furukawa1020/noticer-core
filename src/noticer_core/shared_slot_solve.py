"""Deterministic exact offline allocation for finite public tapes."""

from dataclasses import dataclass

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_hall import HallCut, verify_hall_cut
from noticer_core.shared_slot_verify import Placement, verify_assignment


@dataclass(frozen=True)
class SharedSlotSolution:
    """A complete allocation, or a partial allocation with a sufficient deficit."""

    placements: tuple[Placement, ...]
    deficit: HallCut | None


def solve_shared_slots(case: SharedSlotCase) -> SharedSlotSolution:
    """Find a maximum assignment by augmenting paths with bounded slot cloning."""
    eligibility = {action.name: action.slots for action in case.actions}
    choices = {
        name: tuple((s, clone) for s in slots for clone in range(case.capacities[s]))
        for name, slots in eligibility.items()
    }
    owners: dict[tuple[int, int], str] = {}

    def augment(name: str, visited: set[tuple[int, int]]) -> bool:
        for clone in choices[name]:
            if clone in visited:
                continue
            visited.add(clone)
            if clone not in owners or augment(owners[clone], visited):
                owners[clone] = name
                return True
        return False

    for name in sorted(choices):
        augment(name, set())
    placements = tuple(sorted((name, slot) for (slot, _), name in owners.items()))
    unmatched = set(choices) - {name for name, _ in placements}
    if not unmatched:
        if not verify_assignment(case, placements):
            raise RuntimeError("invalid complete allocation")
        return SharedSlotSolution(placements, None)

    reverse: dict[int, set[str]] = {}
    for name, slot in placements:
        reverse.setdefault(slot, set()).add(name)
    reachable = set(unmatched)
    pending = sorted(unmatched)
    neighbors: set[int] = set()
    while pending:
        for slot in eligibility[pending.pop()]:
            if slot in neighbors:
                continue
            neighbors.add(slot)
            for owner in reverse.get(slot, ()):
                if owner not in reachable:
                    reachable.add(owner)
                    pending.append(owner)
    cut = HallCut(tuple(sorted(reachable)), tuple(sorted(neighbors)))
    if not verify_hall_cut(case, cut) or not verify_assignment(case, placements, complete=False):
        raise RuntimeError("invalid deficient allocation")
    return SharedSlotSolution(placements, cut)
