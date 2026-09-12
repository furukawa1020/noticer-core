"""Pre-registered adaptive attackers for matched-action runtime traces."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


class AdaptiveAttackError(ValueError):
    """Raised when an attack protocol or dataset is invalid."""


class ObserverFamily(StrEnum):
    CLAIM_ONLY = "claim_only"
    FULL_TRACE = "full_trace"
    SIDE_CHANNEL = "timing_size_failure"
    SERVICE_COLLUSION = "service_collusion"
    LONGITUDINAL = "longitudinal"


class ModelFamily(StrEnum):
    LINEAR = "linear"
    TREE = "tree"
    BOOSTING = "boosting"
    SEQUENCE = "sequence"


@dataclass(frozen=True)
class AdaptiveAttackProtocol:
    query_budget: int
    longitudinal_t: int
    seed: int


@dataclass(frozen=True)
class AdaptiveAttackSplit:
    train: np.ndarray
    development: np.ndarray
    test: np.ndarray


@dataclass(frozen=True)
class AdaptiveAttackDataset:
    labels: np.ndarray
    pair_ids: np.ndarray
    family_ids: np.ndarray
    session_ids: np.ndarray
    views: dict[ObserverFamily, np.ndarray]


@dataclass(frozen=True)
class AdaptiveAttackPrediction:
    observer: ObserverFamily
    model: ModelFamily
    truth: np.ndarray
    scores: np.ndarray
    predicted: np.ndarray
    test_indices: np.ndarray


def run_adaptive_attack_suite(
    dataset: AdaptiveAttackDataset,
    split: AdaptiveAttackSplit,
    protocol: AdaptiveAttackProtocol,
) -> tuple[AdaptiveAttackPrediction, ...]:
    """Run the frozen 5-by-4 attack matrix without touching test labels."""
    _validate(dataset, split, protocol)
    calibration = np.concatenate((split.train, split.development))
    rng = np.random.default_rng(protocol.seed)
    selected = np.sort(
        rng.choice(
            calibration,
            size=min(protocol.query_budget, len(calibration)),
            replace=False,
        )
    )
    outputs = []
    for observer in ObserverFamily:
        raw = dataset.views[observer]
        features = _observer_features(raw, observer, protocol.longitudinal_t)
        for offset, model_family in enumerate(ModelFamily):
            model_features = (
                _sequence_features(raw, protocol.longitudinal_t)
                if model_family is ModelFamily.SEQUENCE
                else features
            )
            model = _model(model_family, protocol.seed + offset)
            model.fit(model_features[selected], dataset.labels[selected])
            scores = model.predict_proba(model_features[split.test])[:, 1]
            outputs.append(
                AdaptiveAttackPrediction(
                    observer=observer,
                    model=model_family,
                    truth=dataset.labels[split.test].copy(),
                    scores=scores,
                    predicted=(scores >= 0.5).astype(np.int8),
                    test_indices=split.test.copy(),
                )
            )
    return tuple(outputs)


def _model(model: ModelFamily, seed: int):
    if model is ModelFamily.LINEAR or model is ModelFamily.SEQUENCE:
        return Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=500,
                        random_state=seed,
                        solver="lbfgs",
                    ),
                ),
            ]
        )
    if model is ModelFamily.TREE:
        return DecisionTreeClassifier(max_depth=6, min_samples_leaf=4, random_state=seed)
    return HistGradientBoostingClassifier(
        max_iter=30,
        max_leaf_nodes=15,
        min_samples_leaf=4,
        random_state=seed,
    )


def _observer_features(
    values: np.ndarray,
    observer: ObserverFamily,
    longitudinal_t: int,
) -> np.ndarray:
    if observer is ObserverFamily.LONGITUDINAL:
        return _sequence_features(values, longitudinal_t)
    if values.ndim != 2:
        raise AdaptiveAttackError(f"{observer.value} view must be two-dimensional")
    return values


def _sequence_features(values: np.ndarray, longitudinal_t: int) -> np.ndarray:
    sequence = values[:, :longitudinal_t]
    if sequence.ndim == 2:
        sequence = sequence[:, :, np.newaxis]
    if sequence.ndim != 3 or sequence.shape[1] < longitudinal_t:
        raise AdaptiveAttackError("sequence view is shorter than longitudinal_t")
    delta = np.diff(sequence, axis=1)
    return np.concatenate(
        (
            sequence.mean(axis=1),
            sequence.std(axis=1),
            sequence.min(axis=1),
            sequence.max(axis=1),
            sequence[:, 0],
            sequence[:, -1],
            delta.mean(axis=1),
            delta.std(axis=1),
        ),
        axis=1,
    )


def _validate(
    dataset: AdaptiveAttackDataset,
    split: AdaptiveAttackSplit,
    protocol: AdaptiveAttackProtocol,
) -> None:
    if protocol.query_budget < 2 or protocol.longitudinal_t < 2:
        raise AdaptiveAttackError("query budget and longitudinal_t must be at least two")
    count = len(dataset.labels)
    if set(dataset.views) != set(ObserverFamily):
        raise AdaptiveAttackError("all five observer views are required")
    if any(len(values) != count for values in dataset.views.values()):
        raise AdaptiveAttackError("observer view length mismatch")
    if set(np.unique(dataset.labels)) != {0, 1}:
        raise AdaptiveAttackError("binary private-side labels are required")
    groups = (dataset.pair_ids, dataset.family_ids, dataset.session_ids)
    for values in groups:
        if len(values) != count:
            raise AdaptiveAttackError("group length mismatch")
        sets = [set(values[indices]) for indices in (split.train, split.development, split.test)]
        overlaps = (
            not sets[0].isdisjoint(sets[1])
            or not sets[0].isdisjoint(sets[2])
            or not sets[1].isdisjoint(sets[2])
        )
        if overlaps:
            raise AdaptiveAttackError("pair/family/session split overlap")
    calibration_labels = set(dataset.labels[np.concatenate((split.train, split.development))])
    if calibration_labels != {0, 1} or set(dataset.labels[split.test]) != {0, 1}:
        raise AdaptiveAttackError("calibration and test require both labels")

