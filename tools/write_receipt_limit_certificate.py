"""Export the synthetic single-receiver certificate."""

import argparse
from fractions import Fraction
from pathlib import Path

from noticer_core.receipt_limit_bundle import export_certificate
from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_observer import Observer
from noticer_core.receipt_limit_solve import solve_receipts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    game = crossed_recipients()
    view = Observer(frozenset({"receiver-a"}))
    result = solve_receipts(game, view, Fraction(1, 4))
    if result.certificate is None:
        return 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(export_certificate(game, view, result.certificate))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
