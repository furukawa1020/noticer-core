"""Validation-selected gradient boosting identity attacker for K20."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import balanced_accuracy_score

from noticer_core.attacks.k20_identity import (
    AttackFamily,
    IdentityAttackContractError,
    IdentityAttackPrediction,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
)


@dataclass(slots=True)
class GradientBoostingIdentityAttacker:
    leaf_candidates: tuple[int, ...] = (7, 15, 31)
    max_iter: int = 100
    min_samples_leaf: int = 4
    seed: int = 0
    attacker_id: str = "k20-gradient-boosting-v1"
    family: AttackFamily = field(default=AttackFamily.GRADIENT_BOOSTING, init=False)
    selected_leaves: int | None = field(default=None, init=False)
    _model: HistGradientBoostingClassifier | None = field(default=None, init=False, repr=False)

    def fit(
        self,
        training: LabelledAttackPartition,
        validation: LabelledAttackPartition,
    ) -> None:
        candidates = tuple(sorted(set(self.leaf_candidates)))
        if not candidates or any(value < 2 for value in candidates):
            raise IdentityAttackContractError("boosting leaf candidates must be at least two")
        if self.max_iter < 1 or self.min_samples_leaf < 1:
            raise IdentityAttackContractError("boosting size parameters must be positive")
        training.validate(name="training")
        validation.validate(name="validation")
        scores: list[tuple[float, int]] = []
        for leaves in candidates:
            model = self._new_model(leaves)
            model.fit(training.features, training.labels.astype(str))
            predicted = model.predict(validation.features)
            score = float(balanced_accuracy_score(validation.labels.astype(str), predicted))
            scores.append((score, leaves))
        _, self.selected_leaves = max(scores, key=lambda item: (item[0], -item[1]))
        self._model = self._new_model(self.selected_leaves)
        self._model.fit(
            np.vstack((training.features, validation.features)),
            np.concatenate((training.labels, validation.labels)).astype(str),
        )

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

    def _new_model(self, leaves: int) -> HistGradientBoostingClassifier:
        return HistGradientBoostingClassifier(
            max_iter=self.max_iter,
            max_leaf_nodes=leaves,
            min_samples_leaf=self.min_samples_leaf,
            random_state=self.seed,
        )

