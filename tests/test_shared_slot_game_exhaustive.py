from itertools import combinations_with_replacement, product

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.shared_slot_loss_check import verify_game_loss
from noticer_core.shared_slot_policy_check import verify_policy
from noticer_core.shared_slot_strategy import search_strategy


def _valid_slot_allocations(tape):
    for run in product(*(action.slots for action in tape.actions)):
        if all(run.count(slot) <= cap for slot, cap in enumerate(tape.capacities)):
            yield tuple(
                tuple(action.name for action, chosen in zip(tape.actions, run, strict=True)
                      if chosen == slot)
                for slot in range(len(tape.capacities))
            )


def _causal_by_pairwise_run_enumeration(left, right):
    first_difference = len(left.capacities)
    for slot in range(len(left.capacities)):
        left_view = [slot in action.slots for action in left.actions]
        right_view = [slot in action.slots for action in right.actions]
        if left.capacities[slot] != right.capacities[slot] or left_view != right_view:
            first_difference = slot
            break
    return any(
        left_run[:first_difference] == right_run[:first_difference]
        for left_run, right_run in product(
            _valid_slot_allocations(left), _valid_slot_allocations(right)
        )
    )


def test_strategy_and_loss_match_independent_enumeration_for_272_tape_pairs():
    eligibility = [(0, *(slot for slot in (1, 2) if mask & (1 << (slot - 1))))
                   for mask in range(4)]
    for capacity in ((1, 1, 1), (1, 0, 2)):
        tapes = [
            SharedSlotCase(capacity, (SharedAction("a", 2, a), SharedAction("b", 2, b)))
            for a, b in product(eligibility, repeat=2)
        ]
        for left, right in combinations_with_replacement(tapes, 2):
            game = PublicSlotGame((left, right))
            result = search_strategy(game)
            if _causal_by_pairwise_run_enumeration(left, right):
                assert result.policy is not None and verify_policy(game, result.policy)
            else:
                assert result.loss is not None and verify_game_loss(game, result.loss)
