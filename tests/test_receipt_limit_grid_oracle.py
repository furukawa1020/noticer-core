from collections import Counter
from fractions import Fraction
from itertools import combinations_with_replacement, product

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def _integer_laws(b_slots, observer, q=4):
    # Independent two-action oracle: -1 means withhold; capacity is one.
    plans = [
        (tuple((slot, name) for slot, name in sorted(((a, "a"), (b, "b")))
               if slot >= 0 and name in observer), a >= 0 and b >= 0)
        for a, b in product((-1, 0, 1), (-1, *b_slots))
        if a == -1 or b == -1 or a != b
    ]
    for selected in combinations_with_replacement(plans, q):
        yield Counter(trace for trace, _ in selected), sum(success for _, success in selected)


def test_quarter_mass_oracle_for_small_two_world_fixtures():
    options = ((), (0,), (1,), (0, 1))
    for left, right in combinations_with_replacement(options, 2):
        case = crossed_recipients(left, right)
        for visible in ({"a"}, {"a", "b"}):
            observer = Observer(frozenset(f"receiver-{name}" for name in visible))
            for cap in (0, 2, 4):
                best = 0
                for (p, up), (q, uq) in product(
                    _integer_laws(left, visible), _integer_laws(right, visible)
                ):
                    if min(up, uq) > best and sum(
                        abs(p[key] - q[key]) for key in p.keys() | q.keys()
                    ) <= 2 * cap:
                        best = min(up, uq)
                answer = solve_receipts(case, observer, Fraction(cap, 4))
                assert answer.certificate is not None
                assert answer.certificate.value == Fraction(best, 4)
