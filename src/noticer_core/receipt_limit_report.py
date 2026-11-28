"""Record the tradeoff, no-improvement cases, and incomplete controls together."""

from fractions import Fraction
from typing import Any

from noticer_core.receipt_limit_baseline import common_complete_baseline
from noticer_core.receipt_limit_correlation import correlation_distances
from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_grid import compare_grid
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def build_report(*, grid: bool = False) -> dict[str, Any]:
    """Generate a deterministic report without runtime or environment fields."""
    game = crossed_recipients()
    limited = frozenset({"receiver-a"})
    report: dict[str, Any] = {"schema": "receipt-limit-study.v1", "empirical": False}
    rows = {}
    for key, observer in (
        ("single", Observer(limited)),
        ("coalition", Observer(frozenset({"receiver-a", "receiver-b"}))),
        ("single_failure_visible", Observer(limited, True)),
    ):
        rows[key] = {}
        for delta in (Fraction(), Fraction(1, 4), Fraction(1, 2), Fraction(1)):
            result = solve_receipts(game, observer, delta)
            if result.certificate is None:
                raise RuntimeError("fixture should have a verified result")
            rows[key][str(delta)] = {
                "certified": str(result.certificate.value),
                "common_complete": str(common_complete_baseline(game, observer, delta)),
            }
    report["tradeoff"] = rows
    report["correlation_tv"] = {k: str(v) for k, v in correlation_distances().items()}
    report["controls"] = {
        "invalid": solve_receipts(game, Observer(limited), Fraction(-1)).status,
        "cutoff": solve_receipts(game, Observer(limited), Fraction(), check_steps=1).status,
        "unreachable": str(
            solve_receipts(crossed_recipients((), (0,)), Observer(limited), Fraction(1))
            .certificate.value
        ),
    }
    if grid:
        report["grid"] = compare_grid()
    return report
