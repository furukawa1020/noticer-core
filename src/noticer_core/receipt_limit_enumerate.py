"""Enumerate all finite plans without discarding failures or silent histories."""

from collections.abc import Iterator

from noticer_core.receipt_limit_schedule import Schedule
from noticer_core.shared_slot_contract import SharedSlotCase

MAX_STEPS = 20_000


class ReceiptCutoff(OverflowError):
    """Exploration stopped without a complete proof."""


def enumerate_schedules(
    world: SharedSlotCase, *, max_steps: int = MAX_STEPS
) -> Iterator[Schedule]:
    """Produce valid leaves using capacity pruning and a deterministic order."""
    if type(max_steps) is not int or not 0 < max_steps <= MAX_STEPS:
        raise ValueError("invalid exploration budget")
    used = 0
    actions = sorted(world.actions, key=lambda action: action.name)
    remaining = list(world.capacities)

    def visit(i: int, plan: Schedule) -> Iterator[Schedule]:
        nonlocal used
        used += 1
        if used > max_steps:
            raise ReceiptCutoff("plan enumeration budget exhausted")
        if i == len(actions):
            yield plan
            return
        action = actions[i]
        yield from visit(i + 1, plan)
        for slot in action.slots:
            if remaining[slot]:
                remaining[slot] -= 1
                yield from visit(i + 1, (*plan, (action.name, slot)))
                remaining[slot] += 1

    yield from visit(0, ())
