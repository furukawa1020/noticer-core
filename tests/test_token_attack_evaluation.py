from __future__ import annotations

import pandas as pd

from noticer_core.evaluation.token_attacks import (
    FEATURE_COLUMNS,
    AttackEvaluationConfig,
    build_attack_dataset,
    pair_disjoint_split,
)


def _witnesses(count: int = 12) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "pair_id": range(count),
            "family": ["test"] * count,
            "equivalence_class": [index % 6 for index in range(count)],
            "private_histories_distinct": [True] * count,
            "trace_equal": [True] * count,
            "trace_sha256": [f"{index:064x}" for index in range(count)],
        }
    )


def test_atv2_pair_features_are_exactly_equal_but_controls_leak() -> None:
    dataset = build_attack_dataset(
        _witnesses(),
        AttackEvaluationConfig(horizons=(1,), views=("observer",), bootstrap_samples=0),
    )
    atv2 = dataset[dataset["mechanism"] == "ATv2"]
    for _, pair in atv2.groupby("pair_id"):
        assert pair.iloc[0][list(FEATURE_COLUMNS)].equals(
            pair.iloc[1][list(FEATURE_COLUMNS)]
        )
    broken = dataset[dataset["mechanism"] == "ReadySlotToken"]
    assert all(
        not pair.iloc[0][list(FEATURE_COLUMNS)].equals(
            pair.iloc[1][list(FEATURE_COLUMNS)]
        )
        for _, pair in broken.groupby("pair_id")
    )


def test_pair_split_is_disjoint_and_deterministic() -> None:
    left = pair_disjoint_split(range(20), seed=7, test_fraction=0.3)
    right = pair_disjoint_split(range(20), seed=7, test_fraction=0.3)
    assert left == right
    assert left[0].isdisjoint(left[1])
