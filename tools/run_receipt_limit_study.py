"""Write an exact synthetic study to a specified output file."""

import argparse
import json
from pathlib import Path

from noticer_core.receipt_limit_report import build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--grid", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_report(grid=args.grid), sort_keys=True, indent=2)
    args.output.write_bytes((payload + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
