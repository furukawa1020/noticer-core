from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from noticer_core.evaluation.provenance_attacks import (
    FEATURE_COLUMNS,
    MODEL_NAMES,
    VIEWS,
    ProvenanceAttackConfig,
    evaluate_inference_attacks,
    evaluate_source_attacks,
    generate_attack_dataset,
    group_disjoint_split,
    summarize_criteria,
    validate_public_artifacts,
)


def _config() -> ProvenanceAttackConfig:
    return ProvenanceAttackConfig(
        seed=7,
        n_pairs=32,
        validation_fraction=0.2,
        test_fraction=0.2,
        bootstrap_samples=10,
        source_trials=8,
    )


def test_aepa_pairs_are_equal_and_leaky_controls_are_positive() -> None:
    dataset = generate_attack_dataset(_config())
    aetp = dataset[(dataset["mechanism"] == "AEPA") & (dataset["view"] == "A5_Longitudinal")]
    for _, pair in aetp.groupby("pair_id"):
        assert pair.iloc[0][list(FEATURE_COLUMNS)].equals(
            pair.iloc[1][list(FEATURE_COLUMNS)]
        )
    leaky = dataset[
        (dataset["mechanism"] == "B5_GlobalCollectorKey")
        & (dataset["view"] == "A5_Longitudinal")
    ]
    assert all(
        not pair.iloc[0][list(FEATURE_COLUMNS)].equals(
            pair.iloc[1][list(FEATURE_COLUMNS)]
        )
        for _, pair in leaky.groupby("pair_id")
    )


def test_pair_groups_are_disjoint_and_all_models_metrics_are_present() -> None:
    config = _config()
    dataset = generate_attack_dataset(config)
    split = group_disjoint_split(dataset["pair_id"], config)
    assert not split.train_pairs & split.validation_pairs
    assert not split.train_pairs & split.test_pairs
    assert not split.validation_pairs & split.test_pairs
    results = evaluate_inference_attacks(dataset, split, config)
    assert set(results["model"]) == set(MODEL_NAMES)
    assert set(results["view"]) == set(VIEWS)
    assert {
        "balanced_accuracy",
        "roc_auc",
        "roc_auc_ci95_low",
        "roc_auc_ci95_high",
        "f1",
        "attack_advantage",
    }.issubset(results.columns)
    source = evaluate_source_attacks(config.source_trials)
    criteria = summarize_criteria(
        results,
        source,
        leaky_min_auc=0.8,
        aepa_max_upper_ci=0.6,
    )
    assert criteria["leaky_baselines_passing"] >= 3
    assert criteria["aepa_max_auc_ci_high"] <= 0.6
    assert criteria["source_attack_acceptance_count"] == 0
    assert criteria["all_criteria_passed"] is True


def test_source_spoof_mismatch_and_downgrade_never_act() -> None:
    results = evaluate_source_attacks(16)
    attacks = results[results["attack_id"].str.startswith("S")]
    assert set(attacks["attack_id"]) == {f"S{index}" for index in range(10)}
    assert attacks["accepted"].sum() == 0
    assert attacks["false_action_count"].sum() == 0
    assert attacks["unauthorized_action_count"].sum() == 0
    assert (attacks["source_rejection_rate"] == 1.0).all()


def test_private_artifact_validator_rejects_forbidden_values(tmp_path: Path) -> None:
    pd.DataFrame({"public_metric": [0.5]}).to_csv(tmp_path / "safe.csv", index=False)
    assert validate_public_artifacts(tmp_path)["passed"] is True
    (tmp_path / "bad.json").write_text(
        '{"exact_acquisition_timestamp": 123}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="private artifact validation failed"):
        validate_public_artifacts(tmp_path)
