"""Cross-session temporal linkability attacker for K20."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from noticer_core.data.contracts import WindowDataset


class TemporalLinkabilityError(ValueError):
    """Raised when a session-pair attack contract is invalid."""


@dataclass(frozen=True, slots=True)
class LinkabilitySplit:
    train_sessions: tuple[str, ...]
    validation_sessions: tuple[str, ...]
    test_sessions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LinkabilityResult:
    left_sessions: np.ndarray
    right_sessions: np.ndarray
    truth: np.ndarray
    scores: np.ndarray
    roc_auc: float
    selected_c: float


def run_temporal_linkability_attack(
    dataset: WindowDataset,
    split: LinkabilitySplit,
    *,
    regularization_candidates: tuple[float, ...],
    seed: int,
) -> LinkabilityResult:
    """Infer whether two untouched sessions have the same owner."""
    candidates = tuple(sorted(set(regularization_candidates)))
    if not candidates or any(not np.isfinite(value) or value <= 0 for value in candidates):
        raise TemporalLinkabilityError("regularization candidates must be finite and positive")
    groups = (split.train_sessions, split.validation_sessions, split.test_sessions)
    partitions = [set(values) for values in groups]
    if any(not values for values in partitions):
        raise TemporalLinkabilityError("all session partitions must be non-empty")
    if any(len(group) != len(unique) for group, unique in zip(groups, partitions, strict=True)):
        raise TemporalLinkabilityError("duplicate session within a linkability partition")
    overlaps = (
        partitions[0] & partitions[1]
        or partitions[0] & partitions[2]
        or partitions[1] & partitions[2]
    )
    if overlaps:
        raise TemporalLinkabilityError("linkability session partitions must be disjoint")
    known = set(dataset.session_ids.astype(str))
    if set().union(*partitions) != known:
        raise TemporalLinkabilityError("split must cover every dataset session exactly once")

    embeddings, owners = _session_embeddings(dataset)
    train = _pair_features(split.train_sessions, embeddings, owners)
    validation = _pair_features(split.validation_sessions, embeddings, owners)
    test = _pair_features(split.test_sessions, embeddings, owners)
    scored: list[tuple[float, float]] = []
    for candidate in candidates:
        model = _model(candidate, seed)
        model.fit(train[0], train[1])
        score = roc_auc_score(validation[1], model.predict_proba(validation[0])[:, 1])
        scored.append((float(score), candidate))
    _, selected_c = max(scored, key=lambda item: (item[0], -item[1]))
    model = _model(selected_c, seed)
    model.fit(np.vstack((train[0], validation[0])), np.concatenate((train[1], validation[1])))
    scores = model.predict_proba(test[0])[:, 1]
    return LinkabilityResult(
        left_sessions=test[2],
        right_sessions=test[3],
        truth=test[1],
        scores=scores,
        roc_auc=float(roc_auc_score(test[1], scores)),
        selected_c=selected_c,
    )


def _session_embeddings(dataset: WindowDataset) -> tuple[dict[str, np.ndarray], dict[str, str]]:
    embeddings: dict[str, np.ndarray] = {}
    owners: dict[str, str] = {}
    sessions = dataset.session_ids.astype(str)
    for session in np.unique(sessions):
        indices = np.flatnonzero(sessions == session)
        times = dataset.time_indices[indices]
        if times.dtype.kind not in "iu" or np.any(times < 0):
            raise TemporalLinkabilityError("time indices must be nonnegative integers")
        if len(np.unique(times)) != len(times):
            raise TemporalLinkabilityError("duplicate time index within a session")
        indices = indices[np.argsort(dataset.time_indices[indices], kind="stable")]
        values = dataset.features[indices]
        subjects = np.unique(dataset.subject_ids[indices].astype(str))
        if len(subjects) != 1 or len(values) < 2:
            raise TemporalLinkabilityError("each session requires one owner and two windows")
        delta = np.diff(values, axis=0)
        embeddings[session] = np.concatenate(
            (values.mean(axis=0), values.std(axis=0), values[0], values[-1], delta.mean(axis=0))
        )
        owners[session] = str(subjects[0])
    return embeddings, owners


def _pair_features(
    sessions: tuple[str, ...],
    embeddings: dict[str, np.ndarray],
    owners: dict[str, str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    features: list[np.ndarray] = []
    labels: list[int] = []
    left_ids: list[str] = []
    right_ids: list[str] = []
    ordered = sorted(sessions)
    for left_index, left in enumerate(ordered):
        for right in ordered[left_index + 1 :]:
            features.append(np.abs(embeddings[left] - embeddings[right]))
            labels.append(int(owners[left] == owners[right]))
            left_ids.append(left)
            right_ids.append(right)
    if set(labels) != {0, 1}:
        raise TemporalLinkabilityError("each partition requires same- and different-owner pairs")
    return np.asarray(features), np.asarray(labels), np.asarray(left_ids), np.asarray(right_ids)


def _model(c_value: float, seed: int) -> Pipeline:
    return Pipeline(
        [
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(C=c_value, max_iter=1000, random_state=seed)),
        ]
    )

