"""Synthesize and export a deterministic example proof bundle."""

import argparse
from pathlib import Path

from noticer_core.slot_mix_bundle import export_bundle
from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_solve import solve_mix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    game = asymmetric_game()
    result = solve_mix(game)
    if result.certificate is None:
        return 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(export_bundle(game, result.certificate))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
