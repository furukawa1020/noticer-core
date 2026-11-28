"""Enumerate every pair of two-action readiness patterns in named strata."""

from fractions import Fraction
from itertools import combinations_with_replacement, product

from noticer_core.receipt_limit_baseline import common_complete_baseline
from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def compare_grid() -> dict[str, dict[str, int]]:
    """Keep the no-improvement cases and compare fixed observer projections."""
    options = ((), (0,), (1,), (0, 1))
    output = {}
    for capacity in ((1, 1), (2, 1)):
        stats = dict(pairs=0, checks=0, advantage=0, visibility_decreases=0, status_decreases=0)
        tapes = tuple(
            SharedSlotCase(capacity, (SharedAction("a", 1, a), SharedAction("b", 1, b)))
            for a, b in product(options, repeat=2)
        )
        for first, second in combinations_with_replacement(tapes, 2):
            stats["pairs"] += 1
            problem = ReceiptProblem((first, second), (("a", "alpha"), ("b", "bravo")))
            for delta in (Fraction(), Fraction(1, 4)):
                seen = {}
                for receiver_set in (("alpha",), ("bravo",), ("alpha", "bravo")):
                    for failure in (False, True):
                        observer = Observer(frozenset(receiver_set), failure)
                        answer = solve_receipts(problem, observer, delta)
                        if answer.certificate is None:
                            raise RuntimeError("incomplete grid result")
                        value = answer.certificate.value
                        baseline = common_complete_baseline(problem, observer, delta)
                        assert value >= baseline
                        seen[receiver_set, failure] = value
                        stats["advantage"] += value > baseline
                        stats["checks"] += 1
                joint = seen[("alpha", "bravo"), False]
                singles = [seen[(receiver,), False] for receiver in ("alpha", "bravo")]
                assert all(joint <= single for single in singles)
                stats["visibility_decreases"] += joint < max(singles)
                for subset in (("alpha",), ("bravo",), ("alpha", "bravo")):
                    assert seen[subset, True] <= seen[subset, False]
                stats["status_decreases"] += any(
                    seen[subset, True] < seen[subset, False]
                    for subset in (("alpha",), ("bravo",), ("alpha", "bravo"))
                )
        output[f"{capacity[0]},{capacity[1]}"] = stats
    return output
