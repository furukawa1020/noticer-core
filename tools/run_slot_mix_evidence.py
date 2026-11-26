"""Write reproducible K24 summaries without time or host metadata."""

import argparse
import json
from pathlib import Path

from noticer_core.slot_mix_examples_report import build_mix_examples
from noticer_core.slot_mix_grid import compare_incidence_grid


def main() -> int:
    """Select small fixtures by default, or enumerate the entire comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--grid", action="store_true")
    args = parser.parse_args()
    result = build_mix_examples()
    if args.grid:
        result["grid"] = compare_incidence_grid()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
