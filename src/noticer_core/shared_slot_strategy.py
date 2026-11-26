"""Search finite public uncertainty contracts for a causal deadline policy."""

from dataclasses import dataclass
from typing import Literal

from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_moves import Move, legal_moves, remaining_after
from noticer_core.shared_slot_observations import Observation, refine_tapes

MAX_GAME_MOVES = 12_000


@dataclass(frozen=True)
class PolicyNode:
    """A decision for one observed prefix, with one child per next observation."""

    slot: int
    observation: Observation
    pending: Move
    send: Move
    children: tuple["PolicyNode", ...]


@dataclass(frozen=True)
class LosingMove:
    """A legal move with an immediate miss or one bad future observation."""

    send: Move
    expired: Move
    child: "LossNode | None"


@dataclass(frozen=True)
class LossNode:
    """Proof that every legal decision at this indistinguishable prefix loses."""

    slot: int
    observation: Observation
    pending: Move
    rejected: tuple[LosingMove, ...]


@dataclass(frozen=True)
class StrategySearch:
    """Unverified solver output; only separate proof checks establish evidence."""

    status: Literal["candidate", "no_candidate", "inconclusive", "invalid"]
    policy: PolicyNode | None
    loss: LossNode | None
    moves_examined: int


class _BudgetExhausted(Exception):
    pass


def search_strategy(
    game: PublicSlotGame, *, max_moves: int = MAX_GAME_MOVES
) -> StrategySearch:
    """Choose a move for all tapes in each current public information set."""
    if type(max_moves) is not int or not 0 < max_moves <= MAX_GAME_MOVES:
        return StrategySearch("invalid", None, None, 0)
    deadlines = game.deadlines
    steps = 0

    def visit(
        slot: int, observation: Observation, tapes: tuple[int, ...], pending: Move
    ) -> PolicyNode | LossNode:
        nonlocal steps
        rejected: list[LosingMove] = []
        for send in legal_moves(pending, observation[1], observation[0]):
            if steps >= max_moves:
                raise _BudgetExhausted
            steps += 1
            rest = remaining_after(pending, send)
            expired = tuple(name for name in rest if deadlines[name] <= slot)
            if expired:
                rejected.append(LosingMove(send, expired, None))
                continue
            if not rest:
                return PolicyNode(slot, observation, pending, send, ())
            branches: list[PolicyNode] = []
            for next_view, group in refine_tapes(game, tapes, slot + 1):
                branch = visit(slot + 1, next_view, group, rest)
                if isinstance(branch, LossNode):
                    rejected.append(LosingMove(send, (), branch))
                    break
                branches.append(branch)
            else:
                return PolicyNode(slot, observation, pending, send, tuple(branches))
        return LossNode(slot, observation, pending, tuple(rejected))

    (view, tapes), = refine_tapes(game, tuple(range(len(game.tapes))), 0)
    try:
        result = visit(0, view, tapes, tuple(deadlines))
    except _BudgetExhausted:
        return StrategySearch("inconclusive", None, None, steps)
    if isinstance(result, PolicyNode):
        return StrategySearch("candidate", result, None, steps)
    return StrategySearch("no_candidate", None, result, steps)
