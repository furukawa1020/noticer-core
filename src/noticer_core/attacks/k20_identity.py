"""Model-independent identity attacker contract for K20."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

import numpy as np


class IdentityAttackContractError(ValueError):
    """Raised when an attacker crosses a frozen evaluation boundary."""


class AttackFamily(StrEnum):
    LOGISTIC_REGRESSION = "logistic-regression"
    RANDOM_FOREST = "random-forest"
    GRADIENT_BOOSTING = "gradient-boosting"
    TEMPORAL_LINKABILITY = "temporal-linkability"


@dataclass(frozen=True, slots=True)
class LabelledAttackPartition:
    features: np.ndarray
    labels: np.ndarray
    session_ids: np.ndarray

    def validate(self, *, name: str) -> None:
        _validate_features(self.features, name=name)
        rows = len(self.features)
        if self.labels.shape != (rows,) or self.session_ids.shape != (rows,):
            raise IdentityAttackContractError(f"{name} metadata shape mismatch")
        if len(np.unique(self.labels.astype(str))) < 2:
            raise IdentityAttackContractError(f"{name} requires at least two identity classes")


@dataclass(frozen=True, slots=True)
class UnlabelledAttackPartition:
    features: np.ndarray
    row_ids: np.ndarray
    session_ids: np.ndarray

    def validate(self) -> None:
        _validate_features(self.features, name="test")
        rows = len(self.features)
        if self.row_ids.shape != (rows,) or self.session_ids.shape != (rows,):
            raise IdentityAttackContractError("test metadata shape mismatch")
        if len(np.unique(self.row_ids.astype(str))) != rows:
            raise IdentityAttackContractError("test row_ids must be unique")


@dataclass(frozen=True, slots=True)
class IdentityAttackPrediction:
    attacker_id: str
    family: AttackFamily
    class_labels: tuple[str, ...]
    probabilities: np.ndarray
    predicted_labels: np.ndarray
    row_ids: np.ndarray

    def validate(self) -> None:
        rows = len(self.row_ids)
        classes = len(self.class_labels)
        if not self.attacker_id or not self.attacker_id.isascii():
            raise IdentityAttackContractError("attacker_id must be non-empty ASCII")
        if classes < 2 or len(set(self.class_labels)) != classes:
            raise IdentityAttackContractError("class_labels must contain unique identities")
        if self.probabilities.shape != (rows, classes):
            raise IdentityAttackContractError("probability matrix shape mismatch")
        if self.predicted_labels.shape != (rows,):
            raise IdentityAttackContractError("predicted label shape mismatch")
        if not np.isfinite(self.probabilities).all() or np.any(self.probabilities < 0):
            raise IdentityAttackContractError("probabilities must be finite and non-negative")
        if not np.allclose(self.probabilities.sum(axis=1), 1.0, rtol=0, atol=1e-12):
            raise IdentityAttackContractError("probability rows must sum to one")
        expected = np.asarray(self.class_labels)[np.argmax(self.probabilities, axis=1)]
        if not np.array_equal(self.predicted_labels.astype(str), expected):
            raise IdentityAttackContractError("predicted labels must be probability argmax")


@runtime_checkable
class IdentityAttacker(Protocol):
    attacker_id: str
    family: AttackFamily

    def fit(
        self,
        training: LabelledAttackPartition,
        validation: LabelledAttackPartition,
    ) -> None: ...

    def predict(self, test: UnlabelledAttackPartition) -> IdentityAttackPrediction: ...


def execute_identity_attacker(
    attacker: IdentityAttacker,
    training: LabelledAttackPartition,
    validation: LabelledAttackPartition,
    test: UnlabelledAttackPartition,
) -> IdentityAttackPrediction:
    """Execute an attacker without exposing test truth to fit or predict."""
    training.validate(name="training")
    validation.validate(name="validation")
    test.validate()
    feature_counts = {
        training.features.shape[1],
        validation.features.shape[1],
        test.features.shape[1],
    }
    if len(feature_counts) != 1:
        raise IdentityAttackContractError("feature count differs across partitions")
    train_sessions = set(training.session_ids.astype(str))
    validation_sessions = set(validation.session_ids.astype(str))
    test_sessions = set(test.session_ids.astype(str))
    if train_sessions & validation_sessions or train_sessions & test_sessions:
        raise IdentityAttackContractError("session overlap across attack partitions")
    if validation_sessions & test_sessions:
        raise IdentityAttackContractError("session overlap across attack partitions")
    attacker.fit(training, validation)
    prediction = attacker.predict(test)
    prediction.validate()
    if not np.array_equal(prediction.row_ids.astype(str), test.row_ids.astype(str)):
        raise IdentityAttackContractError("attacker changed test row order")
    return prediction


def _validate_features(features: np.ndarray, *, name: str) -> None:
    if features.ndim != 2 or not len(features) or not features.shape[1]:
        raise IdentityAttackContractError(f"{name} features must be a non-empty matrix")
    if not np.isfinite(features).all():
        raise IdentityAttackContractError(f"{name} features must be finite")

