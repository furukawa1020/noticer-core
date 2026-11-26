"""Write versioned synthetic evidence without timestamps or environment data."""

import argparse
import json
from pathlib import Path

from noticer_core.shared_slot_report import build_shared_slot_report


def main() -> int:
    """Produce a byte-reproducible result at an explicitly requested location."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    output = parser.parse_args().output
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_shared_slot_report(), indent=2, sort_keys=True)
    output.write_bytes((payload + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
