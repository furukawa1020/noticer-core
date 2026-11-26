"""Write checked finite public-game results and proof trees as canonical JSON."""

import argparse
import json
from pathlib import Path

from noticer_core.shared_slot_game_report import build_checked_game_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    output = parser.parse_args().output
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_checked_game_report(), indent=2, sort_keys=True)
    output.write_bytes((payload + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
