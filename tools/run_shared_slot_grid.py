"""Print the complete finite public-slot comparison as stable JSON."""

import json

from noticer_core.shared_slot_comparison import compare_finite_grid


def main() -> int:
    print(json.dumps({"empirical": False, "grid": compare_finite_grid()}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
