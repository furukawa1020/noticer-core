"""Explore loss-free recipient timing and independent bounded fault-model checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from dataclasses import replace
from pathlib import Path

import numpy as np
from run_popets_matched_baselines import Case, _manifest

from noticer_core.attacks.adaptive import AdaptiveAttackDataset, ObserverFamily
from noticer_core.attacks.leaky_control import build_leaky_control
from noticer_core.evaluation import handwritten_controls as handwritten
from noticer_core.evaluation import netshaper_like, pacer_like
from noticer_core.evaluation.aqrs_differential import report_signature
from noticer_core.evaluation.aqrs_oracle import DEFAULT_LIMITS, check_path


def dump(path: Path, result: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def variation(left: list, right: list) -> float:
    """Descriptive TV on finite observed alphabets, not an out-of-sample attack."""
    a, b = Counter(left), Counter(right)
    return sum(abs(a[key] / len(left) - b[key] / len(right)) for key in a.keys() | b.keys()) / 2


def recipient(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines()]
    if [row["seed"] for row in rows] != list(range(100, 164)):
        raise ValueError("recipient measurement is missing a seed or contains duplicates")
    traces: dict[str, list[tuple[int | None, int | None]]] = {}
    due: list[int] = []
    native_equal = 0
    fault_reports: list[tuple[int | None, int | None]] = []
    for row in rows:
        seed, first, second = row["seed"], row["early_ready"], row["late_ready"]
        start, deadline = row["native_window_start"], row["deadline"]
        horizon, size = row["horizon_slots"], row["frame_bytes"]
        if not 0 <= first < second < start <= row["native_action_slot"] <= deadline < horizon:
            raise ValueError("the readiness, authorization or observed-window contract is wrong")
        native_equal += int(row["native_paired_full_trace_equal"])
        if not row["native_paired_full_trace_equal"]:
            raise ValueError("native paired receipt cannot be inferred from differing traces")
        due.append(deadline)
        available = (True,) * horizon
        base = Case("evaluation", seed, "ready-only", 0, horizon, 1, row["slot_ms"],
                    size, start, deadline, row["native_action_slot"], 0, 0, True)
        measured = {
            "native_aetp": (row["native_action_slot"], row["native_action_slot"]),
            "pacer_ready_period_1": [],
            "netshaper_ready_window_1": [],
            "pacer_same_not_before": [],
            "handwritten_deadline": [],
        }
        loss_availability = tuple(slot != deadline for slot in range(horizon + 1))
        fault_slots = []
        for ready in (first, second):
            for tag, service_earliest in (
                ("pacer_ready_period_1", ready), ("pacer_same_not_before", start)
            ):
                actions = (pacer_like.ActionObligation("notify", service_earliest, deadline),)
                pc = pacer_like.PacerLikeConfig(horizon, 1, size)
                manifest = _manifest(
                    base, available, actions, "pacer_like", pacer_like.config_digest(pc)
                )
                run = pacer_like.run_pacer_like(manifest, pc, actions, available)
                measured[tag].append(run.private_deliveries[0].delivered_slot)
            actions = (pacer_like.ActionObligation("notify", ready, deadline),)
            nc = netshaper_like.NetShaperLikeConfig(horizon, 1, size, 1, 0.25, seed)
            manifest = _manifest(
                base, available, actions, "netshaper_like", netshaper_like.config_digest(nc)
            )
            run = netshaper_like.run_netshaper_like(manifest, nc, actions, available)
            measured["netshaper_ready_window_1"].append(run.private_deliveries[0].delivered_slot)
            action = handwritten.MatchedAction("notify", "service-a", deadline, ready, 0)
            config = handwritten.HandwrittenConfig(horizon, size, 1)
            clean = handwritten._run("handwritten_aets", config, action, available)
            fault = handwritten._run(
                "handwritten_aets", replace(config, horizon_slots=horizon + 1),
                action, loss_availability,
            )
            measured["handwritten_deadline"].append(clean.delivered_slot)
            fault_slots.append(fault.delivered_slot)
        fault_reports.append(tuple(fault_slots))
        for name, slots in measured.items():
            traces.setdefault(name, []).append(tuple(slots))
    result = {}
    for name, samples in traces.items():
        early, late = zip(*samples, strict=True)
        result[name] = {
            "different_pairs": sum(a != b for a, b in samples),
            "pairs": len(samples),
            "empirical_tv": variation(early, late),
            "early_slots": sorted(Counter(str(slot) for slot in early).items()),
            "late_slots": sorted(Counter(str(slot) for slot in late).items()),
            "on_time": sum(slot is not None and slot <= due[i]
                           for i, pair in enumerate(samples) for slot in pair),
            "worlds": 2 * len(samples),
        }
    return {
        "evidence": (
            "synthetic, loss-free recipient action issuance proxy; not decryption on a device"
        ),
        "native_source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "native_paired_full_trace_equal": native_equal,
        "absolute_slot_ms": rows[0]["slot_ms"],
        "outer_action_window": [0, due[0]],
        "native_not_before": rows[0]["native_window_start"],
        "results": result,
        "handwritten_deadline_loss_different_pairs": sum(a != b for a, b in fault_reports),
        "handwritten_deadline_loss_on_time": sum(
            slot is not None and slot <= due[i]
            for i, pair in enumerate(fault_reports) for slot in pair
        ),
    }


INPUTS = ("tick", "loss", "retry", "reconnect")
PHASES = ("clean", "lost", "retried")
PATH = ("tick", "loss", "retry", "reconnect", "tick")
HORIZON = len(PATH)


def state(secret: int, mask: int, slot: int, phase: str = "clean") -> str:
    return f"world-{secret}-mask-{mask}-slot-{slot}-{phase}"


def fault_model(*, mutant: bool, view: str) -> dict:
    fields = {
        "service-a": ["receipt-a"],
        "service-b": ["receipt-b"],
        "coalition": ["receipt-a", "receipt-b"],
    }[view]
    states, transitions = [], []
    for secret in (0, 1):
        for mask in (0, 1):
            for slot in range(HORIZON):
                for phase in PHASES:
                    source = state(secret, mask, slot, phase)
                    states.append({
                        "id": source, "action_semantics": "one-notify",
                        "private_history": f"synthetic-ready-{secret}-mask-{mask}",
                    })
                    for symbol in INPUTS:
                        next_phase, observations, actions = phase, {}, []
                        if slot == 1 and symbol == "loss":
                            next_phase = "lost"
                        if slot == 2 and phase == "lost" and symbol == "retry":
                            observations["receipt-a"] = str(mask)
                            next_phase = "retried"
                        if slot == 3 and phase == "retried" and symbol == "reconnect":
                            observations["receipt-b"] = str(mask ^ secret if mutant else mask)
                        if slot == HORIZON - 1:
                            actions.append({
                                "obligation": {"kind": "authorized", "id": "notify"},
                                "action": "notify",
                            })
                        transitions.append({
                            "from": source, "input": symbol,
                            "to": state(secret, mask, min(slot + 1, HORIZON - 1), next_phase),
                            "release": {
                                "emitted": True, "fields": observations, "actions": actions
                            },
                        })
    return {
        "format_version": "aqrs-check-model-v1",
        "horizon": HORIZON,
        "states": states,
        "semantics": [{"id": "one-notify", "obligations": [
            {"id": "notify", "action": "notify", "trigger_slot": 0, "deadline_slot": HORIZON - 1}
        ]}],
        "faults": [{"id": "link-loss", "recovery": None}],
        "inputs": [{"id": x, "public_symbol": x, "fault": "link-loss" if x == "loss" else None}
                   for x in INPUTS],
        "transitions": transitions,
        "observers": [{"id": view, "visible_fields": fields, "observes_actions": True}],
        "initial_pairs": [{"left": state(0, mask, 0), "right": state(1, mask, 0)}
                          for mask in (0, 1)],
    }


def finite_observer_tv(model: dict) -> float:
    """Merge uniform hidden masks under the one explicitly named public fault path."""
    transitions = {(t["from"], t["input"]): t for t in model["transitions"]}
    visible = model["observers"][0]["visible_fields"]
    results: list[list] = [[], []]
    for secret in (0, 1):
        for mask in (0, 1):
            current = state(secret, mask, 0)
            history, action_slots = [], []
            for slot, symbol in enumerate(PATH):
                step = transitions[(current, symbol)]
                history.append(tuple(step["release"]["fields"].get(key) for key in visible))
                if step["release"]["actions"]:
                    action_slots.append(slot)
                current = step["to"]
            if action_slots != [HORIZON - 1]:
                raise ValueError("action utility changed along the observed path")
            results[secret].append(tuple(history))
    return variation(*results)


def run_faults(output: Path, checker: Path) -> dict:
    results = {}
    for mutant in (False, True):
        for view in ("service-a", "service-b", "coalition"):
            variant = "fault-mutant" if mutant else "normalized"
            model = fault_model(mutant=mutant, view=view)
            key = f"{variant}-{view}"
            file = output / f"{key}.model.json"
            dump(file, model)
            python = check_path(file).as_report(engine="python")
            limits = DEFAULT_LIMITS
            completed = subprocess.run(
                [
                    str(checker.resolve()), "--input", str(file.resolve()),
                    "--max-nodes", str(limits.max_nodes), "--max-depth", str(limits.max_depth),
                    "--time-limit-ms", str(limits.time_limit_ms),
                ],
                check=True, capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
            rust = json.loads(completed.stdout)
            results[key] = {
                "engines_agree": report_signature(python) == report_signature(rust),
                "python": python,
                "rust": rust,
                "exact_uniform_mask_tv_given_fault_path": finite_observer_tv(model),
            }
    return {"conditioned_public_input_path": PATH, "results": results}


def leaky_positive_control() -> float:
    """Run the existing K7 side-label feature control apart from the fault mutants."""
    labels = np.array([0, 1, 0, 1])
    groups = np.array(["p0", "p0", "p1", "p1"])
    blank = AdaptiveAttackDataset(
        labels, groups, groups, groups,
        {kind: np.zeros((4, 2, 1) if kind is ObserverFamily.LONGITUDINAL else (4, 2))
         for kind in ObserverFamily},
    )
    controlled = build_leaky_control(blank, source_dataset_sha256="a" * 64, amplitude=1)
    feature = controlled.dataset.views[ObserverFamily.SERVICE_COLLUSION][:, 0]
    return variation(feature[labels == 0].tolist(), feature[labels == 1].tolist())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_jsonl", type=Path)
    parser.add_argument("checker", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    timing = recipient(args.native_jsonl)
    fault = run_faults(args.output, args.checker)
    fault["existing_k7_leaky_control_tv"] = leaky_positive_control()
    dump(args.output / "recipient-summary.json", timing)
    dump(args.output / "checker-summary.json", fault)
    print(json.dumps(timing, indent=2))
    for name, row in fault["results"].items():
        outcome = row["python"]
        print(name, row["engines_agree"], outcome["status"], outcome.get("slot"),
              outcome.get("causal_field"), row["exact_uniform_mask_tv_given_fault_path"])
    print("positive control empirical TV:", fault["existing_k7_leaky_control_tv"])


if __name__ == "__main__":
    main()
