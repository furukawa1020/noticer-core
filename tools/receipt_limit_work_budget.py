"""Report portable enumeration work units under explicit horizon bounds."""

import json
from fractions import Fraction

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def main() -> int:
    rows = []
    for n in range(1, 6):
        names = tuple(f"action{i}" for i in range(n))
        case = SharedSlotCase(
            (n,) * n, tuple(SharedAction(name, n - 1, tuple(range(n))) for name in names)
        )
        problem = ReceiptProblem((case, case), tuple((name, "one") for name in names))
        observer = Observer(frozenset({"one"}))
        bound = (n + 1) ** n
        rows.append({
            "actions_and_slots": n,
            "assignments_per_world": bound,
            "cutoff_below_bound": solve_receipts(
                problem, observer, Fraction(), check_steps=bound - 1
            ).status,
            "at_bound": solve_receipts(problem, observer, Fraction(), check_steps=bound).status,
        })
    print(json.dumps(rows, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
