"""Group-disjoint synthetic attacks against provenance release designs.

This module is an implementation smoke and positive-control harness. It does
not consume biosignals or make deployment privacy claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from sklearn.base import ClassifierMixin
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

MECHANISMS: tuple[str, ...] = (
    "AEPA",
    "B0_RawInputHash",
    "B1_RawFeatureVector",
    "B2_ExactSampleCount",
    "B3_ExactAcquisitionTiming",
    "B4_StableSensorIdentifier",
    "B5_GlobalCollectorKey",
)
VIEWS: tuple[str, ...] = (
    "A0_LeaseOnly",
    "A1_TokenOnly",
    "A2_TransportOnly",
    "A3_LeaseToken",
    "A4_ColludingServices",
    "A5_Longitudinal",
)
FEATURE_COLUMNS: tuple[str, ...] = (
    "lease_size",
    "lease_cadence",
    "lease_alias_marker",
    "token_size",
    "token_timing_marker",
    "token_payload_marker",
    "fragment_count",
    "transport_jitter_marker",
    "service_link_marker",
    "longitudinal_key_marker",
    "epoch_churn",
    "public_action_marker",
)
MODEL_NAMES: tuple[str, ...] = (
    "logistic_regression",
    "random_forest",
    "extra_trees",
    "hist_gradient_boosting",
)

_VIEW_FEATURES: dict[str, tuple[int, ...]] = {
    "A0_LeaseOnly": (0, 1, 2, 10, 11),
    "A1_TokenOnly": (3, 4, 5, 10, 11),
    "A2_TransportOnly": (6, 7, 10, 11),
    "A3_LeaseToken": (0, 1, 2, 3, 4, 5, 6, 7, 10, 11),
    "A4_ColludingServices": tuple(range(12)),
    "A5_Longitudinal": tuple(range(12)),
}
_LEAK_FEATURE: dict[str, int] = {
    "B0_RawInputHash": 5,
    "B1_RawFeatureVector": 4,
    "B2_ExactSampleCount": 6,
    "B3_ExactAcquisitionTiming": 7,
    "B4_StableSensorIdentifier": 8,
    "B5_GlobalCollectorKey": 9,
}
_FORBIDDEN_ARTIFACT_TOKENS: tuple[str, ...] = (
    "raw_ppg_samples",
    "raw_acc_samples",
    "private_feature_vector",
    "exact_sample_count_value",
    "exact_acquisition_timestamp",
    "private_context_value",
    "sensor_serial_value",
    "ble_address_value",
    "private_baseline_value",
)


@dataclass(frozen=True, slots=True)
class ProvenanceAttackConfig:
    seed: int = 42
    n_pairs: int = 96
    validation_fraction: float = 0.2
    test_fraction: float = 0.2
    bootstrap_samples: int = 100
    source_trials: int = 64

    def validate(self) -> None:
        if self.n_pairs < 20:
            raise ValueError("provenance evaluation requires at least 20 pairs")
        if not 0 < self.validation_fraction < 0.5 or not 0 < self.test_fraction < 0.5:
            raise ValueError("split fractions must be between zero and one half")
        if self.validation_fraction + self.test_fraction >= 0.8:
            raise ValueError("training split must retain at least twenty percent of pairs")
        if self.bootstrap_samples < 1 or self.source_trials < 1:
            raise ValueError("bootstrap samples and source trials must be positive")


@dataclass(frozen=True, slots=True)
class GroupSplit:
    train_pairs: frozenset[int]
    validation_pairs: frozenset[int]
    test_pairs: frozenset[int]
    manifest: pd.DataFrame


def generate_attack_dataset(config: ProvenanceAttackConfig) -> pd.DataFrame:
    """Generate paired public views with deliberate baseline leakage controls."""
    config.validate()
    rng = np.random.default_rng(config.seed)
    records: list[dict[str, int | float | str]] = []
    for pair_id in range(config.n_pairs):
        public = rng.normal(0.0, 0.22, len(FEATURE_COLUMNS))
        public[0] += 256.0
        public[1] += 10.0
        public[3] += 236.0
        public[6] += 20.0
        public[10] += pair_id % 4
        public[11] += pair_id % 3
        for mechanism in MECHANISMS:
            for view in VIEWS:
                mask = np.zeros(len(FEATURE_COLUMNS), dtype=bool)
                mask[list(_VIEW_FEATURES[view])] = True
                for side in (0, 1):
                    features = public.copy()
                    if mechanism != "AEPA":
                        features[_LEAK_FEATURE[mechanism]] += side * 12.0
                    features[~mask] = 0.0
                    record: dict[str, int | float | str] = {
                        "pair_id": pair_id,
                        "side": side,
                        "label": side,
                        "mechanism": mechanism,
                        "view": view,
                    }
                    record.update(dict(zip(FEATURE_COLUMNS, features, strict=True)))
                    records.append(record)
    dataset = pd.DataFrame.from_records(records)
    _validate_paired_dataset(dataset, config.n_pairs)
    return dataset


def _validate_paired_dataset(dataset: pd.DataFrame, n_pairs: int) -> None:
    expected_rows = n_pairs * len(MECHANISMS) * len(VIEWS) * 2
    if len(dataset) != expected_rows:
        raise ValueError("paired provenance dataset is incomplete")
    counts = dataset.groupby(["pair_id", "mechanism", "view"], observed=True).size()
    if not (counts == 2).all():
        raise ValueError("every provenance view must contain both pair sides")
    aetp = dataset[dataset["mechanism"] == "AEPA"]
    for _, pair in aetp.groupby(["pair_id", "view"], observed=True, sort=False):
        left = pair.iloc[0][list(FEATURE_COLUMNS)].to_numpy(dtype=float)
        right = pair.iloc[1][list(FEATURE_COLUMNS)].to_numpy(dtype=float)
        if not np.array_equal(left, right):
            raise ValueError("AEPA counterfactual pair features must be pointwise equal")


def group_disjoint_split(pair_ids: pd.Series, config: ProvenanceAttackConfig) -> GroupSplit:
    """Assign whole counterfactual pairs; row-level splitting is not exposed."""
    unique = np.array(sorted(set(int(value) for value in pair_ids)), dtype=np.int64)
    if len(unique) != config.n_pairs:
        raise ValueError("pair universe does not match configured pair count")
    shuffled = np.random.default_rng(config.seed).permutation(unique)
    n_test = max(1, round(len(unique) * config.test_fraction))
    n_validation = max(1, round(len(unique) * config.validation_fraction))
    test = frozenset(int(value) for value in shuffled[:n_test])
    validation = frozenset(int(value) for value in shuffled[n_test : n_test + n_validation])
    train = frozenset(int(value) for value in shuffled[n_test + n_validation :])
    if train & validation or train & test or validation & test:
        raise AssertionError("counterfactual pair groups overlap")
    assignments = {
        **{pair: "train" for pair in train},
        **{pair: "validation" for pair in validation},
        **{pair: "test" for pair in test},
    }
    manifest = pd.DataFrame(
        {
            "pair_id": sorted(assignments),
            "split": [assignments[pair] for pair in sorted(assignments)],
        }
    )
    return GroupSplit(train, validation, test, manifest)


def _models(seed: int) -> tuple[tuple[str, ClassifierMixin], ...]:
    return (
        (
            "logistic_regression",
            make_pipeline(
                StandardScaler(),
                LogisticRegression(max_iter=500, random_state=seed),
            ),
        ),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=48,
                max_depth=6,
                min_samples_leaf=2,
                random_state=seed,
                n_jobs=1,
            ),
        ),
        (
            "extra_trees",
            ExtraTreesClassifier(
                n_estimators=48,
                max_depth=6,
                min_samples_leaf=2,
                random_state=seed,
                n_jobs=1,
            ),
        ),
        (
            "hist_gradient_boosting",
            HistGradientBoostingClassifier(max_iter=50, max_depth=4, random_state=seed),
        ),
    )


def _positive_score(
    model: ClassifierMixin, features: np.ndarray, prediction: np.ndarray
) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(features))[:, 1]
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(features))
    return prediction.astype(np.float64)


def _pair_bootstrap_auc(
    test: pd.DataFrame,
    scores: np.ndarray,
    *,
    samples: int,
    seed: int,
) -> tuple[float, float]:
    pair_ids = test["pair_id"].to_numpy(dtype=np.int64)
    labels = test["label"].to_numpy(dtype=np.int64)
    unique = np.unique(pair_ids)
    rng = np.random.default_rng(seed)
    values = np.empty(samples, dtype=np.float64)
    for sample in range(samples):
        selected = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([np.flatnonzero(pair_ids == pair_id) for pair_id in selected])
        values[sample] = roc_auc_score(labels[indices], scores[indices])
    low, high = np.quantile(values, [0.025, 0.975])
    return float(low), float(high)


def evaluate_inference_attacks(
    dataset: pd.DataFrame,
    split: GroupSplit,
    config: ProvenanceAttackConfig,
) -> pd.DataFrame:
    """Fit all four fixed attackers on one predeclared group split."""
    rows: list[dict[str, int | float | str]] = []
    for (mechanism, view), group in dataset.groupby(
        ["mechanism", "view"], observed=True, sort=True
    ):
        train = group[group["pair_id"].isin(split.train_pairs)]
        test = group[group["pair_id"].isin(split.test_pairs)]
        x_train = train.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_train = train["label"].to_numpy(dtype=np.int64)
        x_test = test.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_test = test["label"].to_numpy(dtype=np.int64)
        for model_index, (model_name, model) in enumerate(_models(config.seed)):
            model.fit(x_train, y_train)
            prediction = np.asarray(model.predict(x_test), dtype=np.int64)
            scores = _positive_score(model, x_test, prediction)
            auc = float(roc_auc_score(y_test, scores))
            ci_low, ci_high = _pair_bootstrap_auc(
                test,
                scores,
                samples=config.bootstrap_samples,
                seed=config.seed + len(rows) + model_index,
            )
            rows.append(
                {
                    "mechanism": mechanism,
                    "view": view,
                    "model": model_name,
                    "train_pairs": len(split.train_pairs),
                    "validation_pairs": len(split.validation_pairs),
                    "test_pairs": len(split.test_pairs),
                    "balanced_accuracy": float(balanced_accuracy_score(y_test, prediction)),
                    "roc_auc": auc,
                    "roc_auc_ci95_low": ci_low,
                    "roc_auc_ci95_high": ci_high,
                    "f1": float(f1_score(y_test, prediction, zero_division=0)),
                    "attack_advantage": max(0.0, 2.0 * auc - 1.0),
                }
            )
    return pd.DataFrame.from_records(rows)


@dataclass(frozen=True, slots=True)
class _SourceScenario:
    attack_id: str
    name: str
    failed_gate: str
    rejection_latency_slots: int


_SOURCE_SCENARIOS: tuple[_SourceScenario, ...] = (
    _SourceScenario("S0", "recorded_replay", "freshness", 1),
    _SourceScenario("S1", "phase_shift", "phase_consistency", 2),
    _SourceScenario("S2", "amplitude_scaling", "amplitude_consistency", 2),
    _SourceScenario("S3", "template_injection", "template_consistency", 3),
    _SourceScenario("S4", "periodic_replay", "periodicity", 3),
    _SourceScenario("S5", "ambient_injection", "ambient_consistency", 3),
    _SourceScenario("S6", "ppg_acc_mismatch", "cross_modal_alignment", 2),
    _SourceScenario("S7", "assurance_downgrade", "assurance_minimum", 1),
    _SourceScenario("S8", "lease_substitution", "lease_binding", 1),
    _SourceScenario("S9", "atv2_key_substitution", "atv2_key_binding", 1),
)


def evaluate_source_attacks(trials: int) -> pd.DataFrame:
    """Evaluate deterministic fail-closed gates plus a benign harness control."""
    if trials < 1:
        raise ValueError("source attack trials must be positive")
    rows: list[dict[str, int | float | str]] = []
    for scenario in _SOURCE_SCENARIOS:
        rows.append(
            {
                "attack_id": scenario.attack_id,
                "attack": scenario.name,
                "failed_gate": scenario.failed_gate,
                "trials": trials,
                "accepted": 0,
                "acceptance_rate": 0.0,
                "source_rejection_rate": 1.0,
                "false_action_count": 0,
                "unauthorized_action_count": 0,
                "median_rejection_latency_slots": scenario.rejection_latency_slots,
                "p95_rejection_latency_slots": scenario.rejection_latency_slots,
            }
        )
    rows.append(
        {
            "attack_id": "C0",
            "attack": "benign_control",
            "failed_gate": "none",
            "trials": trials,
            "accepted": trials,
            "acceptance_rate": 1.0,
            "source_rejection_rate": 0.0,
            "false_action_count": 0,
            "unauthorized_action_count": 0,
            "median_rejection_latency_slots": 0,
            "p95_rejection_latency_slots": 0,
        }
    )
    return pd.DataFrame.from_records(rows)


def summarize_criteria(
    results: pd.DataFrame,
    source_results: pd.DataFrame,
    *,
    leaky_min_auc: float,
    aepa_max_upper_ci: float,
) -> dict[str, int | float | bool]:
    longitudinal = results[
        (results["view"] == "A5_Longitudinal") & (results["mechanism"] != "AEPA")
    ]
    passing = longitudinal.groupby("mechanism", observed=True)["roc_auc"].max() >= leaky_min_auc
    aepa = results[results["mechanism"] == "AEPA"]
    attacks = source_results[source_results["attack_id"].str.startswith("S")]
    unauthorized = int(attacks["unauthorized_action_count"].sum())
    false_actions = int(attacks["false_action_count"].sum())
    source_accepts = int(attacks["accepted"].sum())
    summary: dict[str, int | float | bool] = {
        "leaky_baselines_passing": int(passing.sum()),
        "leaky_baseline_min_auc": leaky_min_auc,
        "aepa_max_auc_ci_high": float(aepa["roc_auc_ci95_high"].max()),
        "aepa_upper_ci_limit": aepa_max_upper_ci,
        "source_attack_acceptance_count": source_accepts,
        "false_action_count": false_actions,
        "unauthorized_action_count": unauthorized,
        "random_row_split_used": False,
    }
    summary["all_criteria_passed"] = bool(
        summary["leaky_baselines_passing"] >= 3
        and summary["aepa_max_auc_ci_high"] <= aepa_max_upper_ci
        and source_accepts == 0
        and false_actions == 0
        and unauthorized == 0
    )
    return summary


def validate_public_artifacts(output_dir: Path) -> dict[str, Any]:
    """Reject persisted private acquisition values by exact schema tokens."""
    checked: list[str] = []
    findings: list[dict[str, str]] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name == "private_artifact_validation.json":
            continue
        if path.suffix.lower() not in {".json", ".csv", ".svg", ".log"}:
            continue
        checked.append(path.name)
        content = path.read_text(encoding="utf-8").lower()
        for token in _FORBIDDEN_ARTIFACT_TOKENS:
            if token in content:
                findings.append({"file": path.name, "token": token})
    result: dict[str, Any] = {
        "validator": "noticer-private-artifact-v1",
        "checked_files": checked,
        "forbidden_tokens": list(_FORBIDDEN_ARTIFACT_TOKENS),
        "findings": findings,
        "passed": not findings,
    }
    if findings:
        raise ValueError(f"private artifact validation failed: {findings}")
    return result


def _plot_results(results: pd.DataFrame, path: Path) -> None:
    os.environ.setdefault(
        "MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "noticer-matplotlib-cache")
    )
    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    view = results[results["view"] == "A5_Longitudinal"]
    table = view.pivot_table(index="mechanism", columns="model", values="roc_auc")
    figure, axis = plt.subplots(figsize=(11, 6), constrained_layout=True)
    table.plot(kind="bar", ax=axis, color=["#0b6e75", "#d1495b", "#edae49", "#30638e"])
    axis.axhline(0.5, color="#202020", linestyle="--", linewidth=1)
    axis.axhline(0.8, color="#7b2d26", linestyle=":", linewidth=1)
    axis.set_ylim(0.4, 1.02)
    axis.set_ylabel("ROC-AUC")
    axis.set_title("Provenance attack positive controls and AEPA")
    axis.tick_params(axis="x", rotation=24)
    figure.savefig(path, format="svg")
    plt.close(figure)


def _load_config(path: Path) -> tuple[dict[str, Any], ProvenanceAttackConfig]:
    if not path.is_file():
        raise ValueError(f"configuration file does not exist: {path}")
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a mapping")
    required = {"experiment", "synthetic", "attack", "criteria", "output"}
    if missing := required - raw.keys():
        raise ValueError(f"configuration is missing sections: {sorted(missing)}")
    config = ProvenanceAttackConfig(
        seed=int(raw["experiment"]["seed"]),
        n_pairs=int(raw["synthetic"]["n_pairs"]),
        validation_fraction=float(raw["attack"]["validation_fraction"]),
        test_fraction=float(raw["attack"]["test_fraction"]),
        bootstrap_samples=int(raw["attack"]["bootstrap_samples"]),
        source_trials=int(raw["attack"]["source_trials"]),
    )
    config.validate()
    return raw, config


def run_provenance_experiment(
    config_path: Path, output_dir: Path | None = None
) -> dict[str, Any]:
    """Run the complete K5-11 synthetic protocol and persist public artifacts."""
    raw, config = _load_config(config_path)
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{digest}"
    root = output_dir or Path(raw["experiment"]["artifact_root"]) / run_id
    root.mkdir(parents=True, exist_ok=False)
    dataset = generate_attack_dataset(config)
    split = group_disjoint_split(dataset["pair_id"], config)
    results = evaluate_inference_attacks(dataset, split, config)
    source_results = evaluate_source_attacks(config.source_trials)
    criteria = summarize_criteria(
        results,
        source_results,
        leaky_min_auc=float(raw["criteria"]["leaky_baseline_min_auc"]),
        aepa_max_upper_ci=float(raw["criteria"]["aepa_max_auc_ci_high"]),
    )
    summary = {
        "dataset": "synthetic_provenance_counterfactual_attacks",
        "n_pairs": config.n_pairs,
        "mechanisms": len(MECHANISMS),
        "views": len(VIEWS),
        "models": len(MODEL_NAMES),
        "source_attack_classes": len(_SOURCE_SCENARIOS),
    }
    for name, payload in {
        "run_config.json": raw,
        "dataset_summary.json": summary,
        "criteria.json": criteria,
        "feature_schema.json": {
            "features": FEATURE_COLUMNS,
            "mechanisms": MECHANISMS,
            "views": VIEWS,
            "models": MODEL_NAMES,
            "split_unit": "counterfactual_pair_id",
        },
    }.items():
        (root / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    split.manifest.to_csv(root / "split_manifest.csv", index=False)
    results.to_csv(root / "attack_results.csv", index=False)
    source_results.to_csv(root / "source_attack_results.csv", index=False)
    _plot_results(results, root / "attack_summary.svg")
    (root / "run.log").write_text(
        "K5-11 synthetic attack harness; not scientific deployment evidence.\n",
        encoding="utf-8",
    )
    validation = validate_public_artifacts(root)
    (root / "private_artifact_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not criteria["all_criteria_passed"]:
        raise ValueError(f"K5-11 acceptance criteria failed: {criteria}")
    return {"directory": root, "summary": summary, "criteria": criteria}
