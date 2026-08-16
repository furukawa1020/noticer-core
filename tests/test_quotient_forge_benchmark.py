from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from noticer_core.evaluation.quotient_forge_benchmark import (
    ABLATIONS,
    CASE_CATALOG,
    FEATURE_COLUMNS,
    MODEL_NAMES,
    SCALABILITY_VALUES,
    BenchmarkConfig,
    case_family_counts,
    counterfactual_group_split,
    evaluate_ablations,
    evaluate_attacks,
    evaluate_cases,
    evaluate_scalability,
    generate_counterfactual_dataset,
    pointwise_equality,
    run_benchmark,
)


def _config() -> BenchmarkConfig:
    return BenchmarkConfig(
        seed=7,
        pairs_per_case=12,
        validation_fraction=0.2,
        test_fraction=0.2,
        timeout_work_units=800,
    )


def test_catalog_contains_noticer_generic_and_unrealizable_cases() -> None:
    counts = case_family_counts()
    assert counts["noticer"] >= 4
    assert counts["generic"] >= 4
    assert counts["unrealizable"] >= 3
    assert len({case.case_id for case in CASE_CATALOG}) == len(CASE_CATALOG)


def test_finite_search_matches_every_expected_outcome_and_records_metrics() -> None:
    results = evaluate_cases()
    assert results["expected_match"].all()
    assert results[results["expected_realizable"]]["security_verified"].all()
    assert results[results["expected_realizable"]]["utility_satisfied"].all()
    assert (results["synthesis_time_ms"] >= 0).all()
    assert (results["search_nodes"] > 0).all()
    assert (results[results["expected_realizable"]]["cost"] > 0).all()


def test_counterfactual_pairs_are_pointwise_equal_and_group_disjoint() -> None:
    config = _config()
    dataset = generate_counterfactual_dataset(config)
    equality = pointwise_equality(dataset)
    protected = equality[equality["mechanism"] == "quotient_forge"]
    control = equality[equality["mechanism"] == "leaky_control"]
    assert (protected["pointwise_equality"] == 1.0).all()
    assert (control["pointwise_equality"] == 0.0).all()
    split = counterfactual_group_split(dataset, config)
    assert not split.train_pairs & split.validation_pairs
    assert not split.train_pairs & split.test_pairs
    assert not split.validation_pairs & split.test_pairs
    assert list(split.manifest.columns) == ["counterfactual_pair_id", "split"]


def test_four_attackers_are_chance_on_protected_and_positive_on_control() -> None:
    config = _config()
    dataset = generate_counterfactual_dataset(config)
    split = counterfactual_group_split(dataset, config)
    results = evaluate_attacks(dataset, split, config)
    assert set(results["model"]) == set(MODEL_NAMES)
    assert set(results["mechanism"]) == {"quotient_forge", "leaky_control"}
    assert (results["split_unit"] == "counterfactual_pair_id").all()
    protected = results[results["mechanism"] == "quotient_forge"]
    controls = results[results["mechanism"] == "leaky_control"]
    assert protected["roc_auc"].max() <= 0.60
    assert controls["roc_auc"].min() >= 0.90
    assert set(FEATURE_COLUMNS).isdisjoint(results.columns)


def test_scalability_records_all_axes_time_and_timeouts() -> None:
    results = evaluate_scalability(_config())
    assert set(results["axis"]) == set(SCALABILITY_VALUES)
    assert results["timed_out"].any()
    assert (results["synthesis_time_ms"] >= 0).all()
    assert set(results["status"]) == {"COMPLETE", "TIMEOUT"}


def test_all_six_ablation_boundaries_are_reported() -> None:
    results = evaluate_ablations()
    assert set(results["ablation"]) == {ablation.name for ablation in ABLATIONS}
    no_quotient = results.loc[results["ablation"] == "without_quotient"].iloc[0]
    no_checker = results.loc[results["ablation"] == "without_checker"].iloc[0]
    no_optimization = results.loc[results["ablation"] == "without_optimization"].iloc[0]
    assert no_quotient["security_verified_rate"] < 1.0
    assert no_checker["security_verified_rate"] == 0.0
    full_cost = pd.DataFrame.from_records(
        [
            {"cost": result}
            for result in evaluate_cases()
            .query("expected_realizable")
            .loc[:, "cost"]
            .to_list()
        ]
    )["cost"].mean()
    assert no_optimization["mean_cost"] > full_cost


def test_runner_writes_only_aggregate_public_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "k6-12"
    result = run_benchmark(
        Path("configs/quotient_forge/benchmark_smoke.yaml"), output
    )
    expected = {
        "run_config.json",
        "summary.json",
        "feature_schema.json",
        "case_results.csv",
        "pointwise_equality.csv",
        "split_manifest.csv",
        "attack_results.csv",
        "scalability.csv",
        "ablations.csv",
        "run.log",
        "public_artifact_validation.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    validation = json.loads(
        (output / "public_artifact_validation.json").read_text(encoding="utf-8")
    )
    assert summary["all_criteria_passed"] is True
    assert summary["row_random_split_used"] is False
    assert validation["passed"] is True
    assert result["artifact_root"] == output
