"""Run a local microbenchmark; timings are not part of deterministic evidence."""

import json
import platform
from statistics import median
from time import perf_counter_ns

from noticer_core.shared_slot_scale import scaling_cases
from noticer_core.shared_slot_solve import solve_shared_slots


def main() -> int:
    rows = []
    for case_name, case in scaling_cases():
        result = solve_shared_slots(case)
        durations = []
        for _ in range(21):
            start = perf_counter_ns()
            solve_shared_slots(case)
            durations.append(perf_counter_ns() - start)
        rows.append({
            "case": case_name,
            "assigned": len(result.placements),
            "requested": len(case.actions),
            "median_us": round(median(durations) / 1000, 2),
        })
    print(json.dumps({
        "platform": platform.platform(),
        "python": platform.python_version(),
        "repetitions": 21,
        "rows": rows,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
