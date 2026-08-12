"""Evaluate counterfactual AETP traces produced by the Rust simulator."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

MODEL_FACTORIES: dict[str, Callable[[int], object]] = {
    "LogisticRegression": lambda seed: make_pipeline(
        StandardScaler(), LogisticRegression(max_iter=1_000, random_state=seed)
    ),
    "RandomForestClassifier": lambda seed: RandomForestClassifier(
        n_estimators=100, min_samples_leaf=2, random_state=seed, n_jobs=-1
    ),
    "HistGradientBoostingClassifier": lambda seed: HistGradientBoostingClassifier(
        max_iter=100, random_state=seed
    ),
    "ExtraTreesClassifier": lambda seed: ExtraTreesClassifier(
        n_estimators=100, min_samples_leaf=2, random_state=seed, n_jobs=-1
    ),
}

VIEWS = {
    "allowed_semantics": ["semantics_code", "public_epoch"],
    "timing_only": [
        "action_slot",
        "interarrival_mean",
        "interarrival_variance",
        "silence_slots",
        "packet_count",
        "drop_rate",
    ],
    "full_network": [
        "action_slot",
        "interarrival_mean",
        "interarrival_variance",
        "silence_slots",
        "packet_count",
        "packet_size_mean",
        "packet_size_variance",
        "drop_rate",
        "cipher_bin_0",
        "cipher_bin_1",
    ],
    "service_view": [
        "semantics_code",
        "public_epoch",
        "service_action_slot",
        "packet_count",
    ],
    "collusion": [
        "semantics_code",
        "service_action_slot",
        "collusion_lag",
        "simultaneous_events",
        "packet_count",
    ],
    "longitudinal": [
        "action_slot",
        "interarrival_variance",
        "silence_slots",
        "packet_count",
        "cipher_bin_0",
        "cipher_bin_1",
        "collusion_lag",
        "simultaneous_events",
        "horizon",
    ],
}


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    mechanism: str
    view: str
    horizon: int
    model: str
    validation_auc: float
    test_auc: float
    balanced_accuracy: float
    macro_f1: float
    attack_advantage: float
    scores: np.ndarray
    predictions: np.ndarray
    labels: np.ndarray
    groups: np.ndarray


def _group_split(groups: pd.Series) -> np.ndarray:
    def assignment(value: str) -> str:
        digest = hashlib.sha256(value.encode()).digest()[0] % 10
        if digest < 6:
            return "train"
        if digest < 8:
            return "validation"
        return "test"

    return groups.astype(str).map(assignment).to_numpy()


def _evaluate_scenario(
    frame: pd.DataFrame,
    mechanism: str,
    view: str,
    horizon: int,
    seed: int,
) -> tuple[list[ScenarioResult], ScenarioResult]:
    selected = frame[(frame["mechanism"] == mechanism) & (frame["horizon"] == horizon)].copy()
    split = _group_split(selected["pair_group_id"])
    features = selected[VIEWS[view]].to_numpy(dtype=float)
    labels = selected["world_label"].to_numpy(dtype=int)
    results: list[ScenarioResult] = []
    fitted: list[tuple[float, ScenarioResult]] = []
    for offset, (name, factory) in enumerate(MODEL_FACTORIES.items()):
        model = factory(seed + offset)
        model.fit(features[split == "train"], labels[split == "train"])
        validation_scores = model.predict_proba(features[split == "validation"])[:, 1]
        validation_auc = float(roc_auc_score(labels[split == "validation"], validation_scores))
        test_scores = model.predict_proba(features[split == "test"])[:, 1]
        predicted = (test_scores >= 0.5).astype(int)
        balanced = float(balanced_accuracy_score(labels[split == "test"], predicted))
        result = ScenarioResult(
            mechanism=mechanism,
            view=view,
            horizon=horizon,
            model=name,
            validation_auc=validation_auc,
            test_auc=float(roc_auc_score(labels[split == "test"], test_scores)),
            balanced_accuracy=balanced,
            macro_f1=float(f1_score(labels[split == "test"], predicted, average="macro")),
            attack_advantage=2.0 * balanced - 1.0,
            scores=test_scores,
            predictions=predicted,
            labels=labels[split == "test"],
            groups=selected.loc[split == "test", "pair_group_id"].to_numpy(),
        )
        results.append(result)
        fitted.append((validation_auc, result))
    return results, max(fitted, key=lambda item: item[0])[1]


def _paired_bootstrap(result: ScenarioResult, seed: int, samples: int = 300) -> dict[str, float]:
    rng = np.random.default_rng(seed)
    groups = np.unique(result.groups)
    balanced_values = np.empty(samples)
    auc_values = np.empty(samples)
    for sample in range(samples):
        chosen = rng.choice(groups, size=len(groups), replace=True)
        indices = np.concatenate([np.flatnonzero(result.groups == group) for group in chosen])
        balanced_values[sample] = balanced_accuracy_score(
            result.labels[indices], result.predictions[indices]
        )
        auc_values[sample] = roc_auc_score(result.labels[indices], result.scores[indices])
    return {
        "balanced_accuracy_ci95_lower": float(np.quantile(balanced_values, 0.025)),
        "balanced_accuracy_ci95_upper": float(np.quantile(balanced_values, 0.975)),
        "roc_auc_ci95_lower": float(np.quantile(auc_values, 0.025)),
        "roc_auc_ci95_upper": float(np.quantile(auc_values, 0.975)),
    }


def _paired_permutation_p_value(result: ScenarioResult, seed: int, samples: int = 300) -> float:
    rng = np.random.default_rng(seed)
    observed = abs(result.test_auc - 0.5)
    exceed = 0
    for _ in range(samples):
        permuted = result.labels.copy()
        for group in np.unique(result.groups):
            indices = np.flatnonzero(result.groups == group)
            if rng.random() < 0.5:
                permuted[indices] = permuted[indices[::-1]]
        if abs(roc_auc_score(permuted, result.scores) - 0.5) >= observed:
            exceed += 1
    return (exceed + 1.0) / (samples + 1.0)


def _mmd(frame: pd.DataFrame, columns: list[str], seed: int) -> float:
    rng = np.random.default_rng(seed)
    left = frame.loc[frame["world_label"] == 0, columns].to_numpy(dtype=float)
    right = frame.loc[frame["world_label"] == 1, columns].to_numpy(dtype=float)
    count = min(256, len(left), len(right))
    left = left[rng.choice(len(left), count, replace=False)]
    right = right[rng.choice(len(right), count, replace=False)]
    scale = np.std(np.vstack([left, right]), axis=0)
    scale[scale == 0] = 1.0
    left /= scale
    right /= scale

    def kernel(first: np.ndarray, second: np.ndarray) -> np.ndarray:
        distance = ((first[:, None, :] - second[None, :, :]) ** 2).sum(axis=2)
        return np.exp(-distance / max(1, first.shape[1]))

    return float(kernel(left, left).mean() + kernel(right, right).mean() - 2 * kernel(left, right).mean())


def _result_row(result: ScenarioResult) -> dict[str, float | int | str]:
    return {
        "mechanism": result.mechanism,
        "view": result.view,
        "horizon": result.horizon,
        "model": result.model,
        "validation_roc_auc": result.validation_auc,
        "test_roc_auc": result.test_auc,
        "balanced_accuracy": result.balanced_accuracy,
        "macro_f1": result.macro_f1,
        "attack_advantage": result.attack_advantage,
    }


def evaluate_artifacts(artifact_dir: Path, *, seed: int = 42) -> dict[str, object]:
    dataset_path = artifact_dir / "attack_dataset.csv"
    if not dataset_path.is_file():
        raise ValueError(f"missing Rust attack dataset: {dataset_path}")
    frame = pd.read_csv(dataset_path)
    all_results: list[ScenarioResult] = []
    best: dict[tuple[str, str, int], ScenarioResult] = {}

    for mechanism in sorted(frame["mechanism"].unique()):
        results, selected = _evaluate_scenario(frame, mechanism, "timing_only", 1, seed)
        all_results.extend(results)
        best[(mechanism, "timing_only", 1)] = selected
    for view in ("allowed_semantics", "full_network", "service_view", "collusion"):
        results, selected = _evaluate_scenario(frame, "AETS", view, 1, seed + 20)
        all_results.extend(results)
        best[("AETS", view, 1)] = selected
    for horizon in (1, 4, 16, 64):
        results, selected = _evaluate_scenario(frame, "AETS", "longitudinal", horizon, seed + 40)
        all_results.extend(results)
        best[("AETS", "longitudinal", horizon)] = selected

    attack_rows = [_result_row(result) for result in all_results]
    pd.DataFrame(attack_rows).to_csv(artifact_dir / "attack_results.csv", index=False)
    bootstrap_rows = []
    for index, ((mechanism, view, horizon), result) in enumerate(best.items()):
        interval = _paired_bootstrap(result, seed + index)
        bootstrap_rows.append(
            {
                "mechanism": mechanism,
                "view": view,
                "horizon": horizon,
                **interval,
                "paired_permutation_p_value": _paired_permutation_p_value(result, seed + 100 + index),
            }
        )
    bootstrap = pd.DataFrame(bootstrap_rows)
    bootstrap.to_csv(artifact_dir / "bootstrap_results.csv", index=False)

    allowed_advantage = best[("AETS", "allowed_semantics", 1)].attack_advantage
    ablation_rows = []
    for mechanism in (
        "ImmediateRelease",
        "FixedSizeOnly",
        "CoarseBucket",
        "EvidenceDependentSlot",
        "SharedServiceRng",
        "AETS",
    ):
        result = best[(mechanism, "timing_only", 1)]
        ablation_rows.append(
            {
                **_result_row(result),
                "conditional_excess_trace_advantage": result.attack_advantage - allowed_advantage,
            }
        )
    pd.DataFrame(ablation_rows).to_csv(artifact_dir / "ablation_results.csv", index=False)

    longitudinal_rows = []
    for horizon in (1, 4, 16, 64):
        result = best[("AETS", "longitudinal", horizon)]
        longitudinal_rows.append(
            {
                **_result_row(result),
                "conditional_excess_trace_advantage": result.attack_advantage - allowed_advantage,
            }
        )
    pd.DataFrame(longitudinal_rows).to_csv(
        artifact_dir / "longitudinal_results.csv", index=False
    )

    aets_one = frame[(frame["mechanism"] == "AETS") & (frame["horizon"] == 1)].copy()
    network_columns = ["pair_group_id", "world_label", *VIEWS["full_network"]]
    service_columns = ["pair_group_id", "world_label", *VIEWS["service_view"]]
    collusion_columns = ["pair_group_id", "world_label", *VIEWS["collusion"]]
    aets_one[network_columns].to_parquet(artifact_dir / "trace_network.parquet", index=False)
    aets_one[service_columns].to_parquet(artifact_dir / "trace_service.parquet", index=False)
    aets_one[collusion_columns].to_parquet(artifact_dir / "trace_collusion.parquet", index=False)

    invariant = json.loads((artifact_dir / "invariant_report.json").read_text(encoding="utf-8"))
    utility = json.loads((artifact_dir / "utility_report.json").read_text(encoding="utf-8"))
    intervals = {
        (row["mechanism"], row["view"], int(row["horizon"])): row
        for row in bootstrap_rows
    }
    full = best[("AETS", "full_network", 1)]
    collusion = best[("AETS", "collusion", 1)]
    long64 = best[("AETS", "longitudinal", 64)]
    naive = best[("ImmediateRelease", "timing_only", 1)]
    go = (
        invariant["coupled_network_equality_rate"] == 1.0
        and naive.test_auc >= 0.80
        and intervals[("AETS", "full_network", 1)]["balanced_accuracy_ci95_lower"] <= 0.5
        <= intervals[("AETS", "full_network", 1)]["balanced_accuracy_ci95_upper"]
        and intervals[("AETS", "full_network", 1)]["balanced_accuracy_ci95_upper"] <= 0.58
        and intervals[("AETS", "collusion", 1)]["balanced_accuracy_ci95_upper"] <= 0.60
        and intervals[("AETS", "longitudinal", 64)]["balanced_accuracy_ci95_upper"] <= 0.60
        and utility["action_utility_rate"] == 1.0
        and utility["deadline_misses"] == 0
    )
    aets_frame = frame[(frame["mechanism"] == "AETS") & (frame["horizon"] == 1)]
    report = {
        "security_notion": "Action-Equivalent Trace Privacy",
        "status": "candidate new primitive / proposed security notion",
        "counterfactual_pairs": int(frame["pair_id"].nunique()),
        "pair_families": sorted(frame["family"].unique().tolist()),
        "invariants": invariant,
        "utility": utility,
        "attacks": {
            "ImmediateRelease_timing_auc": naive.test_auc,
            "FixedSizeOnly_timing_auc": best[("FixedSizeOnly", "timing_only", 1)].test_auc,
            "CoarseBucket_timing_auc": best[("CoarseBucket", "timing_only", 1)].test_auc,
            "EvidenceDependentSlot_timing_auc": best[("EvidenceDependentSlot", "timing_only", 1)].test_auc,
            "AETS_timing_auc": best[("AETS", "timing_only", 1)].test_auc,
            "AETS_full_network_auc": full.test_auc,
            "AETS_service_view_auc": best[("AETS", "service_view", 1)].test_auc,
            "AETS_collusion_auc": collusion.test_auc,
            "AETS_longitudinal_64_auc": long64.test_auc,
        },
        "conditional_excess_trace_advantage": {
            "single_bucket": full.attack_advantage - allowed_advantage,
            "64_buckets": long64.attack_advantage - allowed_advantage,
            "collusion": collusion.attack_advantage - allowed_advantage,
        },
        "maximum_mean_discrepancy": {
            "full_network": _mmd(aets_frame, VIEWS["full_network"], seed),
            "collusion": _mmd(aets_frame, VIEWS["collusion"], seed + 1),
        },
        "go_pivot_kill": {
            "decision": "GO" if go else "PIVOT",
            "reason": "All K2 structural, negative-control, statistical, and utility criteria passed."
            if go
            else "At least one preregistered K2 smoke criterion did not pass.",
        },
    }
    (artifact_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_plots(artifact_dir, pd.DataFrame(ablation_rows), pd.DataFrame(longitudinal_rows), frame)
    with (artifact_dir / "run.log").open("a", encoding="utf-8") as handle:
        handle.write("Python AETP attack evaluation complete.\n")
    return report


def _write_plots(
    artifact_dir: Path,
    ablation: pd.DataFrame,
    longitudinal: pd.DataFrame,
    frame: pd.DataFrame,
) -> None:
    figure, axis = plt.subplots(figsize=(10, 5), constrained_layout=True)
    axis.bar(ablation["mechanism"], ablation["attack_advantage"], color="#0f766e")
    axis.set_ylabel("Attack advantage")
    axis.tick_params(axis="x", rotation=20)
    figure.savefig(artifact_dir / "aetp_advantage_by_mechanism.svg")
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7, 5), constrained_layout=True)
    axis.plot(longitudinal["horizon"], longitudinal["attack_advantage"], marker="o")
    axis.set_xscale("log", base=2)
    axis.set_xlabel("Buckets")
    axis.set_ylabel("AETS attack advantage")
    figure.savefig(artifact_dir / "aetp_advantage_by_horizon.svg")
    plt.close(figure)

    sample = frame[(frame["horizon"] == 1) & frame["mechanism"].isin(["ImmediateRelease", "AETS"])].head(80)
    figure, axis = plt.subplots(figsize=(8, 5), constrained_layout=True)
    for mechanism, group in sample.groupby("mechanism"):
        axis.scatter(group["pair_id"], group["action_slot"], label=mechanism, s=18)
    axis.set_xlabel("Pair ID")
    axis.set_ylabel("Observable action slot")
    axis.legend()
    figure.savefig(artifact_dir / "timing_trace_examples.svg")
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate_artifacts(args.artifact_dir)
    attacks = report["attacks"]
    print(f"naive timing attack AUC: {attacks['ImmediateRelease_timing_auc']:.6f}")
    print(f"AETS timing attack AUC: {attacks['AETS_timing_auc']:.6f}")
    print(f"AETS full attack AUC: {attacks['AETS_full_network_auc']:.6f}")
    print(f"AETS collusion attack AUC: {attacks['AETS_collusion_auc']:.6f}")
    print(f"AETS longitudinal 64-bucket AUC: {attacks['AETS_longitudinal_64_auc']:.6f}")
    print(f"artifact directory: {args.artifact_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
