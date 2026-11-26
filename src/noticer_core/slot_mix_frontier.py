"""Construct deterministic representatives of nondominated success sets."""

from dataclasses import dataclass
from functools import cache

from noticer_core.shared_slot_moves import Move, legal_moves, remaining_after
from noticer_core.shared_slot_observations import Observation
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_masks import maximal_masks
from noticer_core.slot_mix_prefix import PublicBelief, initial_belief, successors
from noticer_core.slot_mix_terminal import delivery_status

MAX_WORK = 80_000


class MixLimit(OverflowError):
    """A bounded evaluator did not finish."""


@dataclass
class WorkBudget:
    """Count legal choices and combinations, not wall time."""

    limit: int
    used: int = 0

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 0 < self.limit <= MAX_WORK:
            raise ValueError("invalid work limit")

    def tick(self) -> None:
        """Stop before a result can exceed the configured bound."""
        if self.used >= self.limit:
            raise MixLimit("work budget exhausted")
        self.used += 1


@dataclass(frozen=True)
class Choice:
    """One decision for one observed prefix, including on failing branches."""

    view: Observation
    send: Move
    children: tuple["Choice", ...] = ()


@dataclass(frozen=True)
class Candidate:
    """A policy with an unverified claimed set of successful tapes."""

    mask: int
    root: Choice


def build_frontier(game: SlotMixGame, budget: WorkBudget) -> tuple[Candidate, ...]:
    """Branch on public observations; combine succeeding world sets by union."""
    deadlines = game.public.deadlines

    @cache
    def visit(belief: PublicBelief, pending: Move) -> tuple[Candidate, ...]:
        found: dict[int, Choice] = {}
        capacity, eligible = belief.view
        for send in legal_moves(pending, eligible, capacity):
            budget.tick()
            rest = remaining_after(pending, send)
            state = delivery_status(rest, deadlines, belief.slot)
            if state != "continue":
                mask = belief.mask if state == "complete" else 0
                found.setdefault(mask, Choice(belief.view, send))
                continue
            plans: dict[int, tuple[Choice, ...]] = {0: ()}
            for branch in successors(game, belief):
                additions: dict[int, tuple[Choice, ...]] = {}
                for candidate in visit(branch, rest):
                    for mask, children in plans.items():
                        budget.tick()
                        additions.setdefault(mask | candidate.mask, (*children, candidate.root))
                plans = {mask: additions[mask] for mask in maximal_masks(additions)}
            for mask, children in plans.items():
                found.setdefault(mask, Choice(belief.view, send, children))
        return tuple(Candidate(mask, found[mask]) for mask in maximal_masks(found))

    return visit(initial_belief(game), tuple(deadlines))
