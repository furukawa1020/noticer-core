"""Reproduce the abstract PoPETs recovery table without external dependencies."""

import argparse
import csv
import json
from itertools import combinations, product
from pathlib import Path
from statistics import mean

from noticer_core.recovery_schedule import ScheduleMode, ServiceWindow, compile_public_plan

SERVICES = ("a", "b")
WIDTH = 3
OUTAGE_BUDGET = 1
FRAME_BYTES = 256


def _tapes() -> tuple[tuple[bool, ...], ...]:
    return tuple(
        tuple(index not in missing for index in range(WIDTH))
        for count in range(OUTAGE_BUDGET + 1)
        for missing in combinations(range(WIDTH), count)
    )


def evaluate() -> list[dict[str, str | int | float]]:
    plan = compile_public_plan(
        tuple(ServiceWindow(service, 3, 3 + WIDTH - 1, OUTAGE_BUDGET) for service in SERVICES),
        frame_bytes=FRAME_BYTES,
    )
    outcomes = []
    for mode in ScheduleMode:
        receipt_diff = wire_cross_class_diff = successes = actions = 0
        costs, covers, latencies = [], [], []
        for lanes in product(_tapes(), repeat=len(SERVICES)):
            tape = dict(zip(SERVICES, lanes, strict=True))
            no_action = plan.replay({}, tape, mode=mode)
            for bits in product((False, True), repeat=len(SERVICES)):
                admitted = {
                    service: 0 for service, present in zip(SERVICES, bits, strict=True) if present
                }
                early = plan.replay(admitted, tape, mode=mode)
                late = plan.replay(dict.fromkeys(admitted, 2), tape, mode=mode)
                receipt_diff += early.receipts != late.receipts
                wire_cross_class_diff += early.frames != no_action.frames
                successes += len(early.receipts)
                actions += len(admitted)
                costs.append(early.model_bytes)
                covers.append(early.cover_frames)
                latencies.extend(receipt.slot - 3 for receipt in early.receipts)
        outcomes.append({
            "mode": mode.value,
            "readiness_pairs": len(costs),
            "joint_receipt_differences": receipt_diff,
            "wire_shapes_different_from_idle": wire_cross_class_diff,
            "deadline_successes": successes,
            "promised_actions": actions,
            "mean_model_bytes_per_case": mean(costs),
            "mean_cover_frames_per_case": mean(covers),
            "mean_delay_slots_delivered_only": mean(latencies),
        })
    return outcomes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = evaluate()
    report = {
        "schema": "noticer.popets.synthetic-recovery-matrix.v1",
        "evidence": "bounded synthetic model; not protocol, deployment, or biosignal evidence",
        "window_slots": WIDTH,
        "max_unavailable_per_service": OUTAGE_BUDGET,
        "model_frame_bytes": FRAME_BYTES,
        "results": results,
    }
    with (args.out / "recovery-matrix.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    with (args.out / "recovery-matrix.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(results[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
