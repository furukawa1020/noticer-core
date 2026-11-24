"""Validation-selected logistic identity attacker for K20."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from noticer_core.attacks.k20_identity import (
    AttackFamily,
    IdentityAttackContractError,
    IdentityAttackPrediction,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
)


@dataclass(slots=True)
class LogisticIdentityAttacker:
    candidates: tuple[float, ...] = (0.1, 1.0, 10.0)
    max_iter: int = 1000
    seed: int = 0
    attacker_id: str = "k20-logistic-v1"
    family: AttackFamily = field(default=AttackFamily.LOGISTIC_REGRESSION, init=False)
    selected_c: float | None = field(default=None, init=False)
    _model: Pipeline | None = field(default=None, init=False, repr=False)

    def fit(
        self,
        training: LabelledAttackPartition,
        validation: LabelledAttackPartition,
    ) -> None:
        values = tuple(sorted(set(self.candidates)))
        if not values or any(not np.isfinite(value) or value <= 0 for value in values):
            raise IdentityAttackContractError("logistic C candidates must be finite and positive")
        if self.max_iter < 1:
            raise IdentityAttackContractError("max_iter must be positive")
        training.validate(name="training")
        validation.validate(name="validation")
        scores: list[tuple[float, float]] = []
        for candidate in values:
            model = self._new_model(candidate)
            model.fit(training.features, training.labels.astype(str))
            predicted = model.predict(validation.features)
            score = float(balanced_accuracy_score(validation.labels.astype(str), predicted))
            scores.append((score, candidate))
        _, self.selected_c = max(scores, key=lambda item: (item[0], -item[1]))
        self._model = self._new_model(self.selected_c)
        features = np.vstack((training.features, validation.features))
        labels = np.concatenate((training.labels, validation.labels)).astype(str)
        self._model.fit(features, labels)

    def predict(self, test: UnlabelledAttackPartition) -> IdentityAttackPrediction:
        if self._model is None:
            raise IdentityAttackContractError("attacker must be fitted before prediction")
        test.validate()
        probabilities = self._model.predict_proba(test.features)
        classes = tuple(str(value) for value in self._model.classes_)
        predicted = np.asarray(classes)[np.argmax(probabilities, axis=1)]
        return IdentityAttackPrediction(
            self.attacker_id,
            self.family,
            classes,
            probabilities,
            predicted,
            test.row_ids.copy(),
        )

    def _new_model(self, c_value: float) -> Pipeline:
        return Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        C=c_value,
                        max_iter=self.max_iter,
                        random_state=self.seed,
                        solver="lbfgs",
                    ),
                ),
            ]
        )

