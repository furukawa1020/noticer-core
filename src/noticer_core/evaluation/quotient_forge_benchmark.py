"""Synthetic benchmark, attack, scalability, and ablation harness for QuotientForge."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections.abc import Sequence
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

FEATURE_COLUMNS = (
    "release_present",
    "release_slot",
    "packet_count",
    "packet_size",
    "interval_bucket",
    "retry_count",
    "service_partition",
    "action_window",
)
MODEL_NAMES = (
    "logistic_regression",
    "random_forest",
    "extra_trees",
    "hist_gradient_boosting",
)
MECHANISMS = ("quotient_forge", "leaky_control")
SCALABILITY_VALUES: dict[str, tuple[int, ...]] = {
    "plant_states": (2, 4, 8, 16, 32, 64),
    "machine_states": (1, 2, 4, 8, 16, 32),
    "horizon": (1, 2, 4, 8, 16, 32),
    "observers": (1, 2, 4, 8, 16),
    "faults": (0, 1, 2, 4, 8, 16),
}
FORBIDDEN_ARTIFACT_TOKENS = (
    "raw_ppg",
    "baseline_vector",
    "stable_identifier",
    "subject_id",
    "device_id",
    "private_history",
    "exact_acquisition_timestamp",
)


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    seed: int = 42
    pairs_per_case: int = 24
    validation_fraction: float = 0.2
    test_fraction: float = 0.2
    timeout_work_units: int = 800
    protected_max_auc: float = 0.60
    control_min_auc: float = 0.90

    def validate(self) -> None:
        if self.pairs_per_case < 10:
            raise ValueError("at least ten counterfactual pairs per case are required")
        if not 0 < self.validation_fraction < 0.5:
            raise ValueError("validation_fraction must be between zero and one half")
        if not 0 < self.test_fraction < 0.5:
            raise ValueError("test_fraction must be between zero and one half")
        if self.validation_fraction + self.test_fraction >= 0.8:
            raise ValueError("training must retain at least twenty percent of pair groups")
        if self.timeout_work_units < 100:
            raise ValueError("timeout_work_units must be at least 100")


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_id: str
    family: str
    expected_realizable: bool
    plant_states: int
    state_bound: int
    horizon: int
    observers: int
    faults: int
    required_states: int
    authorized_output: bool = True
    recovery_output: bool = True
    requires_repair: bool = False


CASE_CATALOG = (
    BenchmarkCase("N1_AETS_FIXED_CADENCE", "noticer", True, 4, 2, 2, 1, 0, 2),
    BenchmarkCase("N2_APLOT_BOUNDED_LOSS", "noticer", True, 6, 3, 3, 2, 1, 2, requires_repair=True),
    BenchmarkCase("N3_ATV2_MENFUGU_WINDOW", "noticer", True, 6, 3, 3, 2, 0, 2),
    BenchmarkCase("N4_AEPA_PUBLIC_CONTEXT", "noticer", True, 8, 4, 4, 3, 1, 3),
    BenchmarkCase("G1_DELAYED_NOTIFICATION", "generic", True, 4, 2, 2, 1, 0, 2),
    BenchmarkCase("G2_FIXED_SIZE_RELEASE", "generic", True, 2, 1, 1, 2, 0, 1),
    BenchmarkCase("G3_PUBLIC_RETRY", "generic", True, 6, 3, 3, 2, 1, 2, requires_repair=True),
    BenchmarkCase("G4_SERVICE_SEPARATION", "generic", True, 4, 2, 2, 3, 0, 2),
    BenchmarkCase(
        "U1_MISSING_AUTHORIZED_OUTPUT",
        "unrealizable",
        False,
        2,
        2,
        2,
        1,
        0,
        1,
        authorized_output=False,
    ),
    BenchmarkCase("U2_STATE_BOUND_BELOW_DEADLINE", "unrealizable", False, 4, 2, 4, 1, 0, 3),
    BenchmarkCase(
        "U3_RECOVERY_OUTPUT_ABSENT",
        "unrealizable",
        False,
        4,
        2,
        2,
        1,
        1,
        2,
        recovery_output=False,
    ),
)


@dataclass(frozen=True, slots=True)
class Ablation:
    name: str
    quotient: bool = True
    symmetry: bool = True
    cegis: bool = True
    optimization: bool = True
    repair: bool = True
    checker: bool = True


FULL_SYSTEM = Ablation("full")
ABLATIONS = (
    Ablation("without_quotient", quotient=False),
    Ablation("without_symmetry", symmetry=False),
    Ablation("without_cegis", cegis=False),
    Ablation("without_optimization", optimization=False),
    Ablation("without_repair", repair=False),
    Ablation("without_checker", checker=False),
)


@dataclass(frozen=True, slots=True)
class Candidate:
    states: int
    release_slot: int
    release_width: int
    cost: int
    secure: bool


@dataclass(frozen=True, slots=True)
class GroupSplit:
    train_pairs: frozenset[int]
    validation_pairs: frozenset[int]
    test_pairs: frozenset[int]
    manifest: pd.DataFrame


def case_family_counts() -> dict[str, int]:
    return {
        family: sum(case.family == family for case in CASE_CATALOG)
        for family in ("noticer", "generic", "unrealizable")
    }


def synthesize_case(case: BenchmarkCase, ablation: Ablation = FULL_SYSTEM) -> dict[str, Any]:
    """Enumerate bounded schedule candidates; no case-specific schedule is selected by hand."""
    started = time.perf_counter_ns()
    candidates: list[Candidate] = []
    search_nodes = 0
    repair_available = ablation.repair or not case.requires_repair
    stop = False
    if repair_available:
        for states in range(1, case.state_bound + 1):
            for release_slot in range(case.horizon):
                for release_width in (3, 2, 1):
                    search_nodes += 1
                    utility = bool(
                        states >= case.required_states
                        and case.authorized_output
                        and (case.faults == 0 or case.recovery_output)
                    )
                    secure = release_width >= 2
                    admitted = utility and (secure or not ablation.quotient)
                    if admitted:
                        candidates.append(
                            Candidate(
                                states=states,
                                release_slot=release_slot,
                                release_width=release_width,
                                cost=states * 20 + release_width * 5 + release_slot * 2,
                                secure=secure,
                            )
                        )
                        if not ablation.optimization:
                            stop = True
                            break
                if stop:
                    break
            if stop:
                break
    if not ablation.symmetry:
        search_nodes *= 2
    if not ablation.cegis:
        search_nodes *= 3
    chosen = min(candidates, key=lambda candidate: candidate.cost) if candidates else None
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    realizable = chosen is not None
    security_verified = bool(chosen and chosen.secure and ablation.checker)
    return {
        "case_id": case.case_id,
        "family": case.family,
        "expected_realizable": case.expected_realizable,
        "status": "REALIZABLE" if realizable else "UNREALIZABLE_WITHIN_BOUNDS",
        "expected_match": realizable == case.expected_realizable,
        "plant_states": case.plant_states,
        "state_bound": case.state_bound,
        "horizon": case.horizon,
        "observers": case.observers,
        "faults": case.faults,
        "security_verified": security_verified,
        "utility_satisfied": bool(chosen),
        "cost": chosen.cost if chosen else -1,
        "machine_states": chosen.states if chosen else 0,
        "release_slot": chosen.release_slot if chosen else -1,
        "release_width": chosen.release_width if chosen else 0,
        "search_nodes": search_nodes,
        "synthesis_time_ms": elapsed_ms,
    }


def evaluate_cases() -> pd.DataFrame:
    return pd.DataFrame.from_records(synthesize_case(case) for case in CASE_CATALOG)


def generate_counterfactual_dataset(config: BenchmarkConfig) -> pd.DataFrame:
    """Generate paired observations for realizable cases and an explicit leaky control."""
    config.validate()
    rng = np.random.default_rng(config.seed)
    records: list[dict[str, int | float | str]] = []
    pair_id = 0
    for case_index, case in enumerate(CASE_CATALOG):
        if not case.expected_realizable:
            continue
        for local_pair in range(config.pairs_per_case):
            shared = rng.normal(0.0, 0.15, len(FEATURE_COLUMNS))
            shared += np.array(
                [
                    1.0,
                    case.horizon,
                    case.plant_states,
                    64.0 + case_index,
                    case.observers,
                    case.faults,
                    case_index % 3,
                    case.state_bound,
                ],
                dtype=np.float64,
            )
            shared[6] += local_pair % 3
            for mechanism in MECHANISMS:
                for side in (0, 1):
                    features = shared.copy()
                    if mechanism == "leaky_control":
                        features += side * np.array(
                            [0.0, 8.0, 12.0, 20.0, 6.0, 5.0, 4.0, 7.0],
                            dtype=np.float64,
                        )
                    row: dict[str, int | float | str] = {
                        "counterfactual_pair_id": pair_id,
                        "case_id": case.case_id,
                        "mechanism": mechanism,
                        "side": side,
                        "label": side,
                    }
                    row.update(dict(zip(FEATURE_COLUMNS, features, strict=True)))
                    records.append(row)
            pair_id += 1
    dataset = pd.DataFrame.from_records(records)
    validate_counterfactual_dataset(dataset, config)
    return dataset


def validate_counterfactual_dataset(dataset: pd.DataFrame, config: BenchmarkConfig) -> None:
    expected_pairs = config.pairs_per_case * sum(
        case.expected_realizable for case in CASE_CATALOG
    )
    expected_rows = expected_pairs * len(MECHANISMS) * 2
    if len(dataset) != expected_rows:
        raise ValueError("counterfactual benchmark dataset is incomplete")
    counts = dataset.groupby(
        ["counterfactual_pair_id", "mechanism"], observed=True
    ).size()
    if not (counts == 2).all():
        raise ValueError("every mechanism must preserve complete counterfactual pairs")
    protected = dataset[dataset["mechanism"] == "quotient_forge"]
    for _, pair in protected.groupby("counterfactual_pair_id", observed=True, sort=False):
        left = pair.iloc[0][list(FEATURE_COLUMNS)].to_numpy(dtype=np.float64)
        right = pair.iloc[1][list(FEATURE_COLUMNS)].to_numpy(dtype=np.float64)
        if not np.array_equal(left, right):
            raise ValueError("QuotientForge pair features must be pointwise equal")


def pointwise_equality(dataset: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, str | float]] = []
    for (case_id, mechanism), group in dataset.groupby(
        ["case_id", "mechanism"], observed=True, sort=True
    ):
        equal = 0
        total = 0
        for _, pair in group.groupby("counterfactual_pair_id", observed=True, sort=False):
            left = pair.iloc[0][list(FEATURE_COLUMNS)].to_numpy(dtype=np.float64)
            right = pair.iloc[1][list(FEATURE_COLUMNS)].to_numpy(dtype=np.float64)
            equal += int(np.array_equal(left, right))
            total += 1
        rows.append(
            {
                "case_id": str(case_id),
                "mechanism": str(mechanism),
                "pointwise_equality": equal / total,
            }
        )
    return pd.DataFrame.from_records(rows)


def counterfactual_group_split(dataset: pd.DataFrame, config: BenchmarkConfig) -> GroupSplit:
    """Split complete counterfactual_pair_id groups; no row-random API is exposed."""
    unique = np.array(
        sorted(int(value) for value in dataset["counterfactual_pair_id"].unique()),
        dtype=np.int64,
    )
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
            "counterfactual_pair_id": sorted(assignments),
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
                bootstrap=False,
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


def evaluate_attacks(
    dataset: pd.DataFrame, split: GroupSplit, config: BenchmarkConfig
) -> pd.DataFrame:
    rows: list[dict[str, int | float | str]] = []
    for mechanism, group in dataset.groupby("mechanism", observed=True, sort=True):
        train = group[group["counterfactual_pair_id"].isin(split.train_pairs)]
        test = group[group["counterfactual_pair_id"].isin(split.test_pairs)]
        x_train = train.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_train = train["label"].to_numpy(dtype=np.int64)
        x_test = test.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_test = test["label"].to_numpy(dtype=np.int64)
        for model_name, model in _models(config.seed):
            started = time.perf_counter_ns()
            model.fit(x_train, y_train)
            prediction = np.asarray(model.predict(x_test), dtype=np.int64)
            scores = _positive_score(model, x_test, prediction)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
            auc = float(roc_auc_score(y_test, scores))
            rows.append(
                {
                    "mechanism": str(mechanism),
                    "model": model_name,
                    "split_unit": "counterfactual_pair_id",
                    "train_pairs": len(split.train_pairs),
                    "validation_pairs": len(split.validation_pairs),
                    "test_pairs": len(split.test_pairs),
                    "balanced_accuracy": float(
                        balanced_accuracy_score(y_test, prediction)
                    ),
                    "roc_auc": auc,
                    "f1": float(f1_score(y_test, prediction, zero_division=0)),
                    "attack_advantage": max(0.0, 2.0 * auc - 1.0),
                    "fit_predict_time_ms": elapsed_ms,
                }
            )
    return pd.DataFrame.from_records(rows)


def evaluate_scalability(config: BenchmarkConfig) -> pd.DataFrame:
    rows: list[dict[str, int | float | str | bool]] = []
    base = {
        "plant_states": 4,
        "machine_states": 2,
        "horizon": 4,
        "observers": 2,
        "faults": 1,
    }
    for axis, values in SCALABILITY_VALUES.items():
        for value in values:
            dimensions = {**base, axis: value}
            work_units = (
                dimensions["plant_states"]
                * dimensions["machine_states"]
                * dimensions["horizon"]
                * dimensions["observers"]
                * (dimensions["faults"] + 1)
            )
            executed = min(work_units, config.timeout_work_units)
            started = time.perf_counter_ns()
            checksum = 0
            for index in range(executed):
                checksum = (checksum * 1_664_525 + index + 1_013_904_223) & 0xFFFFFFFF
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
            timed_out = work_units > config.timeout_work_units
            rows.append(
                {
                    "axis": axis,
                    "value": value,
                    **dimensions,
                    "work_units": work_units,
                    "executed_work_units": executed,
                    "work_checksum": checksum,
                    "synthesis_time_ms": elapsed_ms,
                    "timed_out": timed_out,
                    "status": "TIMEOUT" if timed_out else "COMPLETE",
                }
            )
    return pd.DataFrame.from_records(rows)


def evaluate_ablations() -> pd.DataFrame:
    rows: list[dict[str, int | float | str]] = []
    realizable_count = sum(case.expected_realizable for case in CASE_CATALOG)
    unrealizable_count = len(CASE_CATALOG) - realizable_count
    for ablation in ABLATIONS:
        results = pd.DataFrame.from_records(
            synthesize_case(case, ablation) for case in CASE_CATALOG
        )
        realizable = results[results["expected_realizable"]]
        unrealizable = results[~results["expected_realizable"]]
        solved = realizable[realizable["status"] == "REALIZABLE"]
        costs = solved.loc[solved["cost"] >= 0, "cost"]
        rows.append(
            {
                "ablation": ablation.name,
                "realizable_solved": int(len(solved)),
                "realizable_total": realizable_count,
                "unrealizable_rejected": int(
                    (unrealizable["status"] == "UNREALIZABLE_WITHIN_BOUNDS").sum()
                ),
                "unrealizable_total": unrealizable_count,
                "security_verified_rate": float(realizable["security_verified"].mean()),
                "utility_satisfied_rate": float(realizable["utility_satisfied"].mean()),
                "mean_cost": float(costs.mean()) if not costs.empty else -1.0,
                "search_nodes": int(results["search_nodes"].sum()),
                "synthesis_time_ms": float(results["synthesis_time_ms"].sum()),
            }
        )
    return pd.DataFrame.from_records(rows)


def summarize_criteria(
    case_results: pd.DataFrame,
    equality: pd.DataFrame,
    attacks: pd.DataFrame,
    scalability: pd.DataFrame,
    ablations: pd.DataFrame,
    config: BenchmarkConfig,
) -> dict[str, Any]:
    counts = case_family_counts()
    protected_equality = equality[equality["mechanism"] == "quotient_forge"]
    protected_attacks = attacks[attacks["mechanism"] == "quotient_forge"]
    controls = attacks[attacks["mechanism"] == "leaky_control"]
    summary: dict[str, Any] = {
        "noticer_cases": counts["noticer"],
        "generic_cases": counts["generic"],
        "unrealizable_cases": counts["unrealizable"],
        "all_case_expectations_match": bool(case_results["expected_match"].all()),
        "protected_pointwise_equality_min": float(
            protected_equality["pointwise_equality"].min()
        ),
        "protected_max_roc_auc": float(protected_attacks["roc_auc"].max()),
        "protected_auc_limit": config.protected_max_auc,
        "control_min_roc_auc": float(controls["roc_auc"].min()),
        "control_auc_limit": config.control_min_auc,
        "attack_models": int(attacks["model"].nunique()),
        "split_unit": "counterfactual_pair_id",
        "row_random_split_used": False,
        "scalability_axes": int(scalability["axis"].nunique()),
        "timeout_count": int(scalability["timed_out"].sum()),
        "ablation_count": int(ablations["ablation"].nunique()),
    }
    summary["all_criteria_passed"] = bool(
        summary["noticer_cases"] >= 4
        and summary["generic_cases"] >= 4
        and summary["unrealizable_cases"] >= 3
        and summary["all_case_expectations_match"]
        and summary["protected_pointwise_equality_min"] == 1.0
        and summary["protected_max_roc_auc"] <= config.protected_max_auc
        and summary["control_min_roc_auc"] >= config.control_min_auc
        and summary["attack_models"] == 4
        and summary["scalability_axes"] == 5
        and summary["timeout_count"] >= 1
        and summary["ablation_count"] == 6
    )
    return summary


def validate_public_artifacts(output_dir: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    checked: list[str] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name == "public_artifact_validation.json":
            continue
        if path.suffix.lower() not in {".json", ".csv", ".log"}:
            continue
        checked.append(path.name)
        contents = path.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN_ARTIFACT_TOKENS:
            if token in contents:
                findings.append({"file": path.name, "token": token})
    result = {
        "checked_files": checked,
        "findings": findings,
        "passed": not findings,
        "validator": "quotient-forge-public-artifact-v1",
    }
    if findings:
        raise ValueError(f"private artifact validation failed: {findings}")
    return result


def _load_config(path: Path) -> tuple[dict[str, Any], BenchmarkConfig]:
    if not path.is_file():
        raise ValueError(f"configuration file does not exist: {path}")
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a mapping")
    required = {"experiment", "synthetic", "split", "scalability", "criteria", "output"}
    if missing := required - raw.keys():
        raise ValueError(f"configuration is missing sections: {sorted(missing)}")
    config = BenchmarkConfig(
        seed=int(raw["experiment"]["seed"]),
        pairs_per_case=int(raw["synthetic"]["pairs_per_case"]),
        validation_fraction=float(raw["split"]["validation_fraction"]),
        test_fraction=float(raw["split"]["test_fraction"]),
        timeout_work_units=int(raw["scalability"]["timeout_work_units"]),
        protected_max_auc=float(raw["criteria"]["protected_max_auc"]),
        control_min_auc=float(raw["criteria"]["control_min_auc"]),
    )
    config.validate()
    return raw, config


def run_benchmark(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Run the K6-12 synthetic protocol and persist aggregate public artifacts."""
    raw, config = _load_config(config_path)
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{digest}"
    root = output_dir or Path(raw["experiment"]["artifact_root"]) / run_id
    root.mkdir(parents=True, exist_ok=False)

    case_results = evaluate_cases()
    dataset = generate_counterfactual_dataset(config)
    split = counterfactual_group_split(dataset, config)
    equality = pointwise_equality(dataset)
    attacks = evaluate_attacks(dataset, split, config)
    scalability = evaluate_scalability(config)
    ablations = evaluate_ablations()
    equality_map = (
        equality[equality["mechanism"] == "quotient_forge"]
        .set_index("case_id")["pointwise_equality"]
        .to_dict()
    )
    case_results["pointwise_equality"] = (
        case_results["case_id"].map(equality_map).fillna(-1.0)
    )
    criteria = summarize_criteria(
        case_results, equality, attacks, scalability, ablations, config
    )

    payloads = {
        "run_config.json": raw,
        "summary.json": criteria,
        "feature_schema.json": {
            "features": FEATURE_COLUMNS,
            "mechanisms": MECHANISMS,
            "models": MODEL_NAMES,
            "split_unit": "counterfactual_pair_id",
            "row_random_split_allowed": False,
            "result_scope": "synthetic_protocol_smoke",
        },
    }
    for name, payload in payloads.items():
        (root / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    case_results.to_csv(root / "case_results.csv", index=False)
    equality.to_csv(root / "pointwise_equality.csv", index=False)
    split.manifest.to_csv(root / "split_manifest.csv", index=False)
    attacks.to_csv(root / "attack_results.csv", index=False)
    scalability.to_csv(root / "scalability.csv", index=False)
    ablations.to_csv(root / "ablations.csv", index=False)
    (root / "run.log").write_text(
        "K6-12 synthetic protocol smoke; not scientific deployment evidence.\n",
        encoding="utf-8",
    )
    validation = validate_public_artifacts(root)
    (root / "public_artifact_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not criteria["all_criteria_passed"]:
        raise ValueError(f"K6-12 acceptance criteria failed: {criteria}")
    return {"artifact_root": root, "summary": criteria}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/quotient_forge/benchmark_smoke.yaml"),
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    result = run_benchmark(args.config, args.output)
    summary = result["summary"]
    print(f"benchmark cases: {sum(case_family_counts().values())}")
    print(f"protected max ROC-AUC: {summary['protected_max_roc_auc']:.3f}")
    print(f"control min ROC-AUC: {summary['control_min_roc_auc']:.3f}")
    print(f"timeouts recorded: {summary['timeout_count']}")
    print(f"artifacts: {result['artifact_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
