"""Compare causal policies with the same admitted public uncertainty class."""

from itertools import combinations_with_replacement, product

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_loss_check import verify_game_loss
from noticer_core.shared_slot_policy_check import observed, verify_policy
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_strategy import search_strategy
from noticer_core.shared_slot_verify import Placement, verify_assignment


def worst_slack_first(game: PublicSlotGame, realized: int) -> tuple[Placement, ...]:
    """Prioritize actions with the fewest opportunities on any compatible tape.

    The replay controls the observations supplied to the policy. Ranking sees the
    compatible uncertainty class, not the identity of the realized future.
    """
    tape = game.tapes[realized]
    compatible = game.tapes
    deadlines = game.deadlines
    pending = set(deadlines)
    placements = []
    for slot in range(game.horizon):
        capacity, eligible = observed(tape, slot)
        compatible = tuple(
            world for world in compatible if observed(world, slot) == (capacity, eligible)
        )

        def priority(
            name: str, now: int = slot, worlds: tuple[SharedSlotCase, ...] = compatible
        ) -> tuple[int, int, str]:
            opportunities = (
                sum(
                    index >= now and world.capacities[index] > 0
                    for index in action.slots
                )
                for world in worlds for action in world.actions if action.name == name
            )
            return min(opportunities), deadlines[name], name

        choice = sorted(pending.intersection(eligible), key=priority)[:capacity]
        pending.difference_update(choice)
        placements.extend((name, slot) for name in choice)
    return tuple(sorted(placements))


def compare_finite_grid() -> dict[str, dict[str, int]]:
    """Count every pair, including impossible paths, and verify every result."""
    possibilities = [
        (0, *(slot for slot in (1, 2) if bits & (1 << (slot - 1))))
        for bits in range(4)
    ]
    output: dict[str, dict[str, int]] = {}
    for axis, capacity in (("steady", (1, 1, 1)), ("outage_then_burst", (1, 0, 2))):
        tapes = [
            SharedSlotCase(capacity, (SharedAction("a", 2, a), SharedAction("b", 2, b)))
            for a, b in product(possibilities, repeat=2)
        ]
        counts = dict(
            tape_pairs=0, offline_both=0, checked_policy=0, checked_no_policy=0,
            deadline_first_both=0, worst_slack_both=0, inconclusive=0,
        )
        for left, right in combinations_with_replacement(tapes, 2):
            counts["tape_pairs"] += 1
            game = PublicSlotGame((left, right))
            if all(solve_shared_slots(tape).deficit is None for tape in game.tapes):
                counts["offline_both"] += 1
            if all(verify_assignment(tape, deadline_first(tape)) for tape in game.tapes):
                counts["deadline_first_both"] += 1
            if all(
                verify_assignment(tape, worst_slack_first(game, index))
                for index, tape in enumerate(game.tapes)
            ):
                counts["worst_slack_both"] += 1
            result = search_strategy(game)
            if result.policy is not None and verify_policy(game, result.policy):
                counts["checked_policy"] += 1
            elif result.loss is not None and verify_game_loss(game, result.loss):
                counts["checked_no_policy"] += 1
            elif result.status == "inconclusive":
                counts["inconclusive"] += 1
            else:
                raise RuntimeError("unexpected unverified search result")
        output[axis] = counts
    return output
