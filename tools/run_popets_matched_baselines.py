"""Measure K7 network approximations on the native AETP synthetic action windows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
from dataclasses import asdict, dataclass
from itertools import product
from pathlib import Path
from statistics import mean

import numpy as np

from noticer_core.evaluation import netshaper_like, pacer_like
from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    FORMAT_VERSION,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
    SharedContract,
)

FAMILIES = (
    "early_vs_late_evidence",
    "smooth_vs_spiky_signal",
    "different_baseline",
    "different_noise_path",
    "different_subject",
    "different_session",
)
SEEDS = {"development": range(8), "evaluation": range(100, 124)}
PACER_PERIODS = tuple(range(1, 9))
NETSHAPER_CANDIDATES = tuple(product((1, 2, 4, 8), (0.25, 0.5, 1.0, 2.0)))
NATIVE_NAME = "native-aetp"


@dataclass(frozen=True)
class Case:
    split: str
    seed: int
    family: str
    service_index: int
    horizon_slots: int
    services: int
    slot_ms: int
    frame_bytes: int
    window_start: int
    deadline: int
    action_slot: int
    bytes_left: int
    bytes_right: int
    paired_metadata_equal: bool


@dataclass(frozen=True)
class Measurement:
    split: str
    seed: int
    family: str
    mechanism: str
    frame_bytes_per_world: float
    worlds_received: int
    worlds_on_time: int
    latency_left_ms: int | None
    latency_right_ms: int | None
    paired_metadata_equal: bool


def _sha(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def load_cases(path: Path) -> tuple[Case, ...]:
    cases = tuple(
        Case(**json.loads(line)) for line in path.read_text(encoding="utf-8-sig").splitlines()
    )
    expected = {
        (split, seed, family) for split, seeds in SEEDS.items()
        for seed, family in product(seeds, FAMILIES)
    }
    if len(cases) != len(expected) or {(x.split, x.seed, x.family) for x in cases} != expected:
        raise ValueError("native data did not cover the complete frozen case and seed grid")
    for case in cases:
        geometry = (case.horizon_slots, case.services, case.slot_ms, case.frame_bytes)
        if geometry != (256, 4, 250, 236):
            raise ValueError("unexpected native configuration")
        if not 0 <= case.service_index < case.services:
            raise ValueError("invalid service index")
        if not 0 <= case.window_start <= case.deadline < case.horizon_slots:
            raise ValueError("invalid public action window")
        if type(case.paired_metadata_equal) is not bool:
            raise ValueError("paired equality must be explicit")
    return cases


def _manifest(
    case: Case,
    available: tuple[bool, ...],
    actions: tuple[pacer_like.ActionObligation, ...],
    mechanism: str,
    config_hash: str,
) -> ComparisonManifest:
    shared = SharedContract(
        _sha((case.split, case.seed, case.family, case.service_index)),
        _sha(("slot", "service", "bytes")),
        pacer_like.utility_trace_digest(actions),
        pacer_like.fault_trace_digest(available),
        _sha(("frame_bytes", "milliseconds_from_public_window_start", "missed_deadlines")),
        _sha((SEEDS["development"].stop, SEEDS["evaluation"].start, SEEDS["evaluation"].stop)),
        "held_out",
        "development",
    )
    entries = []
    for name in sorted(MECHANISMS):
        selected = name == mechanism
        digest = config_hash if selected else _sha(("contract-placeholder-not-run", name))
        kind = "approximation" if name in {"pacer_like", "netshaper_like", "automata"} else "local"
        entries.append(Mechanism(
            name,
            kind,
            "local-simulator-no-claim" if selected else "not-run-for-this-call",
            "src/noticer_core/evaluation/" + name + ".py" if selected else "not-run-for-this-call",
            "v1",
            (digest,),
            digest,
        ))
    return ComparisonManifest(FORMAT_VERSION, shared, tuple(entries), AXES, True)


def _world(
    case: Case, mechanism: str, setting: tuple[int, float]
) -> tuple[tuple[tuple[int, int, int], ...], int | None]:
    """One queue per public service, including empty service queues."""
    slots, scale = setting
    available = (True,) * case.horizon_slots
    observed: list[tuple[int, int, int]] = []
    delivered: int | None = None
    for channel in range(case.services):
        actions = (
            (pacer_like.ActionObligation("authorized", case.window_start, case.deadline),)
            if channel == case.service_index else ()
        )
        if mechanism == "pacer_like":
            pc = pacer_like.PacerLikeConfig(case.horizon_slots, slots, case.frame_bytes)
            manifest = _manifest(case, available, actions, mechanism, pacer_like.config_digest(pc))
            run = pacer_like.run_pacer_like(manifest, pc, actions, available)
        elif mechanism == "netshaper_like":
            nc = netshaper_like.NetShaperLikeConfig(
                case.horizon_slots, slots, case.frame_bytes, slots, scale,
                104_729 * case.seed + channel,
            )
            manifest = _manifest(
                case, available, actions, mechanism, netshaper_like.config_digest(nc)
            )
            run = netshaper_like.run_netshaper_like(manifest, nc, actions, available)
        else:
            raise ValueError("unknown network mechanism")
        observed.extend(
            (frame.slot, channel, frame.frame_bytes)
            for frame in run.public_trace if frame.transmitted
        )
        if actions:
            delivered = run.private_deliveries[0].delivered_slot
    return tuple(sorted(observed)), delivered


def _measure(case: Case, mechanism: str, setting: tuple[int, float]) -> Measurement:
    if mechanism == NATIVE_NAME:
        bytes_per_world = (case.bytes_left + case.bytes_right) / 2
        deliveries = (case.action_slot, case.action_slot)
        equal = case.paired_metadata_equal
    else:
        # Both worlds passed the same public-window eligibility condition.
        # Couple the public random tape, not the private histories.
        left, left_delivery = _world(case, mechanism, setting)
        right, right_delivery = _world(case, mechanism, setting)
        bytes_per_world = (sum(item[2] for item in left) + sum(item[2] for item in right)) / 2
        deliveries = (left_delivery, right_delivery)
        equal = left == right
    latencies = tuple(
        (slot - case.window_start) * case.slot_ms if slot is not None else None
        for slot in deliveries
    )
    return Measurement(
        case.split, case.seed, case.family, mechanism, bytes_per_world,
        sum(slot is not None for slot in deliveries),
        sum(slot is not None and case.window_start <= slot <= case.deadline for slot in deliveries),
        latencies[0], latencies[1], equal,
    )


def summarize(rows: list[Measurement]) -> dict[str, int | float | None]:
    delivered_latencies = sorted(
        latency for row in rows for latency in (row.latency_left_ms, row.latency_right_ms)
        if latency is not None
    )
    on_time = sum(item.worlds_on_time for item in rows)
    return {
        "pairs": len(rows),
        "worlds": 2 * len(rows),
        "paired_metadata_equal": sum(item.paired_metadata_equal for item in rows),
        "on_time": on_time,
        "missed_deadlines": 2 * len(rows) - on_time,
        "delivered_by_end": sum(item.worlds_received for item in rows),
        "mean_frame_bytes_per_world": mean(item.frame_bytes_per_world for item in rows),
        "mean_delay_ms_delivered_only": mean(delivered_latencies) if delivered_latencies else None,
        "p95_delay_ms_delivered_only": (
            delivered_latencies[(95 * len(delivered_latencies) + 99) // 100 - 1]
            if delivered_latencies else None
        ),
    }


def _select(
    development: tuple[Case, ...], mechanism: str, candidates: tuple[tuple[int, float], ...]
) -> tuple[tuple[int, float], list[dict[str, object]]]:
    ranked = []
    for setting in candidates:
        summary = summarize([_measure(case, mechanism, setting) for case in development])
        delay = summary["mean_delay_ms_delivered_only"]
        values = (
            int(summary["missed_deadlines"] or 0),
            float(summary["mean_frame_bytes_per_world"] or 0),
            float(delay) if delay is not None else float("inf"),
            setting,
        )
        ranked.append((values, {"setting": setting, **summary}))
    ranked.sort(key=lambda item: item[0])
    return ranked[0][0][-1], [item[1] for item in ranked]


def compare(native_path: Path, output: Path) -> None:
    cases = load_cases(native_path)
    development = tuple(case for case in cases if case.split == "development")
    evaluation = tuple(case for case in cases if case.split == "evaluation")
    pacer, pacer_sweep = _select(
        development, "pacer_like", tuple((period, 0.0) for period in PACER_PERIODS)
    )
    netshaper, netshaper_sweep = _select(development, "netshaper_like", NETSHAPER_CANDIDATES)
    eval_runs = {
        NATIVE_NAME: (NATIVE_NAME, (1, 0.0)),
        "pacer_like_development_selected": ("pacer_like", pacer),
        "pacer_like_period_1": ("pacer_like", (1, 0.0)),
        "netshaper_like_development_selected": ("netshaper_like", netshaper),
    }
    report = {
        "schema": "noticer.popets.matched-loss-free-pilot.v1",
        "evidence": "exploratory native synthetic and simulated baseline; not human data",
        "python": platform.python_version(),
        "numpy": np.__version__,
        "native_input_sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
        "development_seeds": list(SEEDS["development"]),
        "evaluation_seeds": list(SEEDS["evaluation"]),
        "families_shared_across_splits": list(FAMILIES),
        "selection": ["missed_deadlines", "mean_frame_bytes_per_world", "mean_delay", "setting"],
        "setting_fields": ["period_or_window_slots", "laplace_scale_frames_not_epsilon"],
        "development_pacer": pacer_sweep,
        "development_netshaper": netshaper_sweep,
        "evaluation": {},
    }
    with (output / "evaluation.csv").open("x", encoding="utf-8", newline="") as file:
        writer = None
        for label, (mechanism, setting) in eval_runs.items():
            rows = [_measure(case, mechanism, setting) for case in evaluation]
            report["evaluation"][label] = {"setting": setting, **summarize(rows)}
            for row in rows:
                record = asdict(row) | {"mechanism": label}
                if writer is None:
                    writer = csv.DictWriter(file, fieldnames=list(record))
                    writer.writeheader()
                writer.writerow(record)
    with (output / "summary.json").open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, allow_nan=False)
        file.write("\n")
    print(json.dumps(report["evaluation"], ensure_ascii=True, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_jsonl", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    compare(args.native_jsonl, args.output)


if __name__ == "__main__":
    main()
