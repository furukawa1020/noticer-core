"""Measure enumeration growth in the abstract first-available recovery model."""

import argparse
import json
from itertools import combinations, islice, product
from math import comb
from pathlib import Path
from time import perf_counter_ns

from noticer_core.recovery_schedule import ScheduleMode, ServiceWindow, compile_public_plan

WIDTH = 3
BUDGET = 1


def collect(scope: tuple[int, ...], cap: int) -> list[dict]:
    if type(cap) is not int or not 1 <= cap <= 1_000_000:
        raise ValueError("cap must be between 1 and 1000000")
    if not scope or any(type(n) is not int or not 1 <= n <= 16 for n in scope):
        raise ValueError("scope contains an unsupported service count")
    lanes = tuple(
        tuple(slot not in missing for slot in range(WIDTH))
        for count in range(BUDGET + 1)
        for missing in combinations(range(WIDTH), count)
    )
    per_lane = sum(comb(WIDTH, count) for count in range(BUDGET + 1))
    results = []
    for count in scope:
        names = tuple(f"s{index:02}" for index in range(count))
        windows = tuple(ServiceWindow(name, 3, 3 + WIDTH - 1, BUDGET) for name in names)
        started = perf_counter_ns()
        plan = compile_public_plan(windows, frame_bytes=256)
        construction_ns = perf_counter_ns() - started
        expected = per_lane**count
        checked = violations = 0
        early, late = dict.fromkeys(names, 0), dict.fromkeys(names, 2)
        started = perf_counter_ns()
        for selection in islice(product(lanes, repeat=count), cap):
            tape = dict(zip(names, selection, strict=True))
            a = plan.replay(early, tape, mode=ScheduleMode.RECIPIENT_ONLY)
            b = plan.replay(late, tape, mode=ScheduleMode.RECIPIENT_ONLY)
            checked += 1
            violations += bool(a != b or a.missed or len(a.receipts) != count)
        elapsed_ns = perf_counter_ns() - started
        status = "failed" if violations else "complete" if checked == expected else "inconclusive"
        results.append({
            "services": count,
            "public_tapes": expected,
            "tapes_checked": checked,
            "observed_violations": violations,
            "status": status,
            "construction_ns": construction_ns,
            "enumeration_ns": elapsed_ns,
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    parser.add_argument("--cap", type=int, default=4096)
    args = parser.parse_args()
    report = {
        "schema": "noticer.k22.synthetic-recovery-scale.v1",
        "bound": args.cap,
        "public_window_slots": WIDTH,
        "max_unavailable_per_window": BUDGET,
        "evidence": "synthetic reference construction and replay; not native synthesis timing",
        "results": collect((2, 4, 8), args.cap),
    }
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
