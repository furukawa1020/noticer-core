"""Attack evaluation for Atypicality Token v2 trace features.

The evaluator consumes only sanitized counterfactual witness rows. It creates
paired public-trace feature controls; it never reads biosignals, evidence
scores, evidence-ready timestamps, or cryptographic keys.
"""

from __future__ import annotations

import argparse
import os
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import ClassifierMixin
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

MECHANISMS: tuple[str, ...] = (
    "ATv2",
    "ReadySlotToken",
    "ScoreBucketToken",
    "VariableLengthToken",
    "PerActionOnlyToken",
    "SharedServiceIdentifierToken",
)
DEFAULT_HORIZONS: tuple[int, ...] = (1, 4, 16, 64)
DEFAULT_VIEWS: tuple[str, ...] = ("observer", "single_service", "colluding_services")
FEATURE_COLUMNS: tuple[str, ...] = (
    "first_release_offset",
    "frame_count",
    "total_bytes",
    "length_variance",
    "score_bucket",
    "service_linkability",
)


@dataclass(frozen=True)
class AttackEvaluationConfig:
    """Deterministic settings for a paired attack evaluation."""

    seed: int = 42
    horizons: tuple[int, ...] = DEFAULT_HORIZONS
    views: tuple[str, ...] = DEFAULT_VIEWS
    test_fraction: float = 0.3
    bootstrap_samples: int = 100


def load_witnesses(path: Path) -> pd.DataFrame:
    """Load and validate sanitized Rust counterfactual witnesses."""

    frame = pd.read_csv(path)
    required = {
        "pair_id",
        "family",
        "equivalence_class",
        "private_histories_distinct",
        "trace_equal",
        "trace_sha256",
    }
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"witness file is missing columns: {sorted(missing)}")
    if frame["pair_id"].duplicated().any():
        raise ValueError("pair_id must be unique")
    if not frame["private_histories_distinct"].astype(bool).all():
        raise ValueError("all counterfactual histories must differ")
    if not frame["trace_equal"].astype(bool).all():
        raise ValueError("ATv2 witness includes a non-equal trace")
    return frame.sort_values("pair_id", kind="stable").reset_index(drop=True)


def build_attack_dataset(
    witnesses: pd.DataFrame,
    config: AttackEvaluationConfig,
) -> pd.DataFrame:
    """Construct paired ATv2 and intentionally broken-control trace features."""

    mechanism_count = len(MECHANISMS)
    horizon_count = len(config.horizons)
    view_count = len(config.views)
    rows_per_pair = mechanism_count * horizon_count * view_count * 2
    pair_count = len(witnesses)

    pair_id = np.repeat(witnesses["pair_id"].to_numpy(dtype=np.int64), rows_per_pair)
    family = np.repeat(witnesses["family"].astype(str).to_numpy(), rows_per_pair)
    equivalence_class = np.repeat(
        witnesses["equivalence_class"].to_numpy(dtype=np.int16), rows_per_pair
    )
    mechanism_index = np.tile(
        np.repeat(np.arange(mechanism_count, dtype=np.int8), horizon_count * view_count * 2),
        pair_count,
    )
    horizon = np.tile(
        np.repeat(np.asarray(config.horizons, dtype=np.int16), view_count * 2),
        pair_count * mechanism_count,
    )
    view_index = np.tile(
        np.repeat(np.arange(view_count, dtype=np.int8), 2),
        pair_count * mechanism_count * horizon_count,
    )
    side = np.tile(
        np.array([0, 1], dtype=np.int8),
        pair_count * mechanism_count * horizon_count * view_count,
    )

    public_jitter = ((pair_id * 1_103_515_245 + 12_345) >> 12) % 7
    first_release_offset = (8 + equivalence_class * 7 + public_jitter).astype(np.float64)
    frame_count = (horizon.astype(np.float64) * 16).astype(np.float64)
    total_bytes = frame_count * 236
    length_variance = np.zeros(len(pair_id), dtype=np.float64)
    score_bucket = (equivalence_class % 4).astype(np.float64)
    service_linkability = ((equivalence_class * 13 + view_index) % 17).astype(np.float64)
    exposure = np.choose(view_index, np.array([1.0, 0.75, 1.25], dtype=np.float64))
    side_float = side.astype(np.float64)

    ready_mask = mechanism_index == MECHANISMS.index("ReadySlotToken")
    first_release_offset[ready_mask] += (
        side_float[ready_mask]
        * np.maximum(2, horizon[ready_mask] // 2)
        * exposure[ready_mask]
    )
    score_mask = mechanism_index == MECHANISMS.index("ScoreBucketToken")
    score_bucket[score_mask] += (
        side_float[score_mask]
        * (3 + horizon[score_mask].astype(np.float64) / 16)
        * exposure[score_mask]
    )
    length_mask = mechanism_index == MECHANISMS.index("VariableLengthToken")
    total_bytes[length_mask] += (
        side_float[length_mask] * 41 * horizon[length_mask] * exposure[length_mask]
    )
    length_variance[length_mask] += side_float[length_mask] * 19 * exposure[length_mask]
    action_only_mask = mechanism_index == MECHANISMS.index("PerActionOnlyToken")
    frame_count[action_only_mask] -= (
        side_float[action_only_mask]
        * np.minimum(frame_count[action_only_mask] - 1, horizon[action_only_mask] * 3)
        * exposure[action_only_mask]
    )
    total_bytes[action_only_mask] = frame_count[action_only_mask] * 236
    identifier_mask = mechanism_index == MECHANISMS.index("SharedServiceIdentifierToken")
    service_linkability[identifier_mask] += (
        side_float[identifier_mask] * 23 * exposure[identifier_mask]
    )

    result = pd.DataFrame(
        {
            "pair_id": pair_id,
            "family": pd.Categorical(family),
            "equivalence_class": equivalence_class,
            "side": side,
            "label": side,
            "mechanism": pd.Categorical.from_codes(mechanism_index, categories=MECHANISMS),
            "horizon_buckets": horizon,
            "view": pd.Categorical.from_codes(view_index, categories=config.views),
            "first_release_offset": first_release_offset,
            "frame_count": frame_count,
            "total_bytes": total_bytes,
            "length_variance": length_variance,
            "score_bucket": score_bucket,
            "service_linkability": service_linkability,
        }
    )
    _assert_pair_contract(result)
    return result


def _assert_pair_contract(dataset: pd.DataFrame) -> None:
    expected = len(MECHANISMS) * len(dataset["horizon_buckets"].unique()) * len(
        dataset["view"].unique()
    )
    counts = dataset.groupby(["pair_id", "side"], sort=False, observed=True).size()
    if not (counts == expected).all():
        raise ValueError("every pair side must have every mechanism/horizon/view")
    atv2 = dataset.loc[dataset["mechanism"] == "ATv2"]
    for _, group in atv2.groupby(
        ["pair_id", "horizon_buckets", "view"], sort=False, observed=True
    ):
        if len(group) != 2 or not np.array_equal(
            group.iloc[0][list(FEATURE_COLUMNS)].to_numpy(dtype=float),
            group.iloc[1][list(FEATURE_COLUMNS)].to_numpy(dtype=float),
        ):
            raise ValueError("ATv2 paired features must be exactly equal")


def pair_disjoint_split(
    pair_ids: Iterable[int],
    *,
    seed: int,
    test_fraction: float,
) -> tuple[set[int], set[int]]:
    """Split pair IDs once so both counterfactual sides stay in one partition."""

    unique = np.array(sorted(set(int(value) for value in pair_ids)), dtype=np.int64)
    if len(unique) < 4:
        raise ValueError("at least four counterfactual pairs are required")
    rng = np.random.default_rng(seed)
    shuffled = rng.permutation(unique)
    test_size = max(1, int(round(len(shuffled) * test_fraction)))
    test = set(int(value) for value in shuffled[:test_size])
    train = set(int(value) for value in shuffled[test_size:])
    if train.intersection(test):
        raise AssertionError("pair split overlap")
    return train, test


def evaluate_attacks(
    dataset: pd.DataFrame,
    config: AttackEvaluationConfig,
) -> pd.DataFrame:
    """Fit four deterministic attacks and return pair-bootstrap intervals."""

    train_pairs, test_pairs = pair_disjoint_split(
        dataset["pair_id"], seed=config.seed, test_fraction=config.test_fraction
    )
    rows: list[dict[str, int | float | str]] = []
    group_columns = ["mechanism", "horizon_buckets", "view"]
    for keys, group in dataset.groupby(group_columns, sort=True, observed=True):
        train = group[group["pair_id"].isin(train_pairs)]
        test = group[group["pair_id"].isin(test_pairs)]
        x_train = train.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_train = train["label"].to_numpy(dtype=np.int64)
        x_test = test.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        y_test = test["label"].to_numpy(dtype=np.int64)
        for model_name, model in _models(config.seed):
            model.fit(x_train, y_train)
            prediction = model.predict(x_test)
            score = _positive_score(model, x_test, prediction)
            balanced = balanced_accuracy_score(y_test, prediction)
            auc = roc_auc_score(y_test, score)
            low, high = _pair_bootstrap_interval(
                test=test,
                prediction=prediction,
                seed=config.seed + len(rows),
                samples=config.bootstrap_samples,
            )
            rows.append(
                {
                    "mechanism": keys[0],
                    "horizon_buckets": int(keys[1]),
                    "view": keys[2],
                    "model": model_name,
                    "train_pairs": len(train_pairs),
                    "test_pairs": len(test_pairs),
                    "balanced_accuracy": balanced,
                    "balanced_accuracy_ci_low": low,
                    "balanced_accuracy_ci_high": high,
                    "roc_auc": auc,
                    "chance_balanced_accuracy": 0.5,
                }
            )
    return pd.DataFrame.from_records(rows)


def _models(seed: int) -> Sequence[tuple[str, ClassifierMixin]]:
    return (
        (
            "logistic_regression",
            make_pipeline(
                StandardScaler(),
                LogisticRegression(max_iter=500, random_state=seed),
            ),
        ),
        ("decision_tree", DecisionTreeClassifier(max_depth=5, random_state=seed)),
        ("gaussian_nb", GaussianNB()),
        (
            "linear_discriminant",
            LinearDiscriminantAnalysis(solver="lsqr", shrinkage="auto"),
        ),
    )


def _positive_score(
    model: ClassifierMixin,
    features: np.ndarray,
    prediction: np.ndarray,
) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(features))[:, 1]
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(features))
    return prediction.astype(np.float64)


def _pair_bootstrap_interval(
    *,
    test: pd.DataFrame,
    prediction: np.ndarray,
    seed: int,
    samples: int,
) -> tuple[float, float]:
    if samples <= 0:
        value = balanced_accuracy_score(test["label"], prediction)
        return float(value), float(value)
    work = test.loc[:, ["pair_id", "label"]].copy()
    work["correct"] = prediction == work["label"].to_numpy()
    contributions = (
        work.groupby(["pair_id", "label"], sort=False, observed=True)["correct"]
        .mean()
        .unstack("label")
        .mean(axis=1)
        .to_numpy(dtype=np.float64)
    )
    rng = np.random.default_rng(seed)
    sampled = rng.choice(contributions, size=(samples, len(contributions)), replace=True)
    values = sampled.mean(axis=1)
    return float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975))


def longitudinal_summary(results: pd.DataFrame) -> pd.DataFrame:
    """Aggregate model results without selecting on the test labels."""

    return (
        results.groupby(["mechanism", "horizon_buckets", "view"], as_index=False)
        .agg(
            mean_balanced_accuracy=("balanced_accuracy", "mean"),
            max_balanced_accuracy=("balanced_accuracy", "max"),
            mean_roc_auc=("roc_auc", "mean"),
        )
        .sort_values(["view", "mechanism", "horizon_buckets"], kind="stable")
    )


def write_summary_figure(longitudinal: pd.DataFrame, path: Path) -> None:
    """Write an SVG overview of observer-view attack accuracy."""

    os.environ.setdefault(
        "MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "noticer-matplotlib-cache")
    )
    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    observer = longitudinal[longitudinal["view"] == "observer"]
    figure, axis = plt.subplots(figsize=(10, 5.5), constrained_layout=True)
    colors = {
        "ATv2": "#127475",
        "ReadySlotToken": "#d1495b",
        "ScoreBucketToken": "#edae49",
        "VariableLengthToken": "#7b2d26",
        "PerActionOnlyToken": "#30638e",
        "SharedServiceIdentifierToken": "#6b4c9a",
    }
    for mechanism, group in observer.groupby("mechanism", sort=False):
        axis.plot(
            group["horizon_buckets"],
            group["mean_balanced_accuracy"],
            marker="o",
            linewidth=2,
            label=mechanism,
            color=colors[mechanism],
        )
    axis.axhline(0.5, color="#252525", linestyle="--", linewidth=1, label="chance")
    axis.set_xscale("log", base=2)
    axis.set_ylim(0.4, 1.02)
    axis.set_xlabel("Observation horizon (public buckets)")
    axis.set_ylabel("Mean balanced accuracy")
    axis.set_title("Counterfactual trace attack controls")
    axis.grid(alpha=0.2)
    axis.legend(fontsize=8, ncol=2)
    figure.savefig(path, format="svg")
    plt.close(figure)


def run_evaluation(
    witness_path: Path,
    output_dir: Path,
    config: AttackEvaluationConfig,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run the complete sanitized evaluator and persist reproducible artifacts."""

    output_dir.mkdir(parents=True, exist_ok=True)
    witnesses = load_witnesses(witness_path)
    dataset = build_attack_dataset(witnesses, config)
    dataset.to_parquet(output_dir / "token_attack_dataset.parquet", index=False)
    results = evaluate_attacks(dataset, config)
    results.to_csv(output_dir / "token_attack_results.csv", index=False)
    longitudinal = longitudinal_summary(results)
    longitudinal.to_csv(output_dir / "longitudinal_results.csv", index=False)
    write_summary_figure(longitudinal, output_dir / "token_attack_summary.svg")
    return results, longitudinal


def _parse_int_list(value: str) -> tuple[int, ...]:
    parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    if not parsed or any(item <= 0 for item in parsed):
        raise argparse.ArgumentTypeError("horizons must be positive comma-separated integers")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--witnesses",
        type=Path,
        default=Path("artifacts/k3_token_v2/counterfactual_witnesses.csv"),
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/k3_token_v2"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--horizons", type=_parse_int_list, default=DEFAULT_HORIZONS)
    parser.add_argument("--bootstrap-samples", type=int, default=100)
    args = parser.parse_args()
    config = AttackEvaluationConfig(
        seed=args.seed,
        horizons=args.horizons,
        bootstrap_samples=args.bootstrap_samples,
    )
    results, _ = run_evaluation(args.witnesses, args.output, config)
    atv2 = results.loc[results["mechanism"] == "ATv2", "balanced_accuracy"]
    print(
        f"K3 attack evaluation complete: {len(results)} model cells; "
        f"ATv2 mean balanced accuracy={atv2.mean():.4f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
