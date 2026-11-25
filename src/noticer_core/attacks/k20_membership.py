"""Prediction-only membership inference smoke attack for K20."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class MembershipAttackError(ValueError):
    """Raised when membership observations violate the smoke protocol."""


@dataclass(frozen=True, slots=True)
class MembershipAttackDataset:
    probabilities: np.ndarray
    true_class_indices: np.ndarray
    membership: np.ndarray
    session_ids: np.ndarray

    def validate(self) -> None:
        if self.probabilities.ndim != 2 or self.probabilities.shape[1] < 2:
            raise MembershipAttackError("probabilities must contain at least two classes")
        rows, classes = self.probabilities.shape
        vectors = (self.true_class_indices, self.membership, self.session_ids)
        if any(values.shape != (rows,) for values in vectors):
            raise MembershipAttackError("membership metadata shape mismatch")
        if not np.isfinite(self.probabilities).all() or np.any(self.probabilities < 0):
            raise MembershipAttackError("probabilities must be finite and non-negative")
        if not np.allclose(self.probabilities.sum(axis=1), 1.0, rtol=0, atol=1e-12):
            raise MembershipAttackError("probability rows must sum to one")
        if np.any(self.true_class_indices < 0) or np.any(self.true_class_indices >= classes):
            raise MembershipAttackError("true class index is outside probability support")
        if set(np.unique(self.membership)) != {0, 1}:
            raise MembershipAttackError("membership labels must contain zero and one")


@dataclass(frozen=True, slots=True)
class MembershipAttackResult:
    truth: np.ndarray
    scores: np.ndarray
    roc_auc: float
    advantage: float


def run_membership_smoke_attack(
    training: MembershipAttackDataset,
    test: MembershipAttackDataset,
    *,
    seed: int,
) -> MembershipAttackResult:
    """Infer membership using output confidence only, never source features."""
    training.validate()
    test.validate()
    if set(training.session_ids.astype(str)) & set(test.session_ids.astype(str)):
        raise MembershipAttackError("membership attack sessions must be disjoint")
    model = Pipeline(
        [
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=1000, random_state=seed)),
        ]
    )
    model.fit(_attack_features(training), training.membership)
    scores = model.predict_proba(_attack_features(test))[:, 1]
    auc = float(roc_auc_score(test.membership, scores))
    return MembershipAttackResult(
        truth=test.membership.copy(),
        scores=scores,
        roc_auc=auc,
        advantage=2.0 * abs(auc - 0.5),
    )


def _attack_features(dataset: MembershipAttackDataset) -> np.ndarray:
    probabilities = np.clip(dataset.probabilities, 1e-15, 1.0)
    rows = np.arange(len(probabilities))
    true_probability = probabilities[rows, dataset.true_class_indices]
    ordered = np.sort(probabilities, axis=1)
    confidence = ordered[:, -1]
    margin = ordered[:, -1] - ordered[:, -2]
    entropy = -np.sum(probabilities * np.log(probabilities), axis=1)
    loss = -np.log(true_probability)
    return np.column_stack((confidence, margin, entropy, true_probability, loss))

