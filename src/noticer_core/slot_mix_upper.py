"""Independent scalar Bellman upper bound, not a success-mask enumeration."""

from fractions import Fraction
from functools import cache

from noticer_core.shared_slot_policy_check import observed
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import WorkBudget


def best_weighted_policy(
    game: SlotMixGame, weights: tuple[Fraction, ...], budget: WorkBudget
) -> Fraction:
    """Maximize weighted complete deliveries using only visible observations."""
    public = game.public
    deadlines = public.deadlines
    if len(weights) != len(public.tapes) or any(weight < 0 for weight in weights):
        raise ValueError("invalid objective weights")

    @cache
    def before(slot: int, group: tuple[int, ...], pending: frozenset[str]) -> Fraction:
        if not pending:
            return sum((weights[i] for i in group), Fraction())
        if slot == public.horizon:
            return Fraction()
        per_view: dict[tuple[int, tuple[str, ...]], list[int]] = {}
        for i in group:
            per_view.setdefault(observed(public.tapes[i], slot), []).append(i)
        total = Fraction()
        for (capacity, eligible), ids in per_view.items():
            actions = tuple(sorted(pending.intersection(eligible)))
            best = Fraction()
            for bits in range(1 << len(actions)):
                if bits.bit_count() > capacity:
                    continue
                budget.tick()
                rest = pending.difference(
                    action for j, action in enumerate(actions) if bits & (1 << j)
                )
                if not any(deadlines[action] <= slot for action in rest):
                    best = max(best, before(slot + 1, tuple(ids), rest))
            total += best
        return total

    return before(0, tuple(range(len(public.tapes))), frozenset(deadlines))
