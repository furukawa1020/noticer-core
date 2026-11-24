"""Validation-selected random forest identity attacker for K20."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

from noticer_core.attacks.k20_identity import (
    AttackFamily,
    IdentityAttackContractError,
    IdentityAttackPrediction,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
)


@dataclass(slots=True)
class RandomForestIdentityAttacker:
    depth_candidates: tuple[int | None, ...] = (4, 8, None)
    n_estimators: int = 128
    min_samples_leaf: int = 2
    seed: int = 0
    attacker_id: str = "k20-random-forest-v1"
    family: AttackFamily = field(default=AttackFamily.RANDOM_FOREST, init=False)
    selected_depth: int | None = field(default=None, init=False)
    _model: RandomForestClassifier | None = field(default=None, init=False, repr=False)

    def fit(
        self,
        training: LabelledAttackPartition,
        validation: LabelledAttackPartition,
    ) -> None:
        if not self.depth_candidates or any(
            depth is not None and depth < 1 for depth in self.depth_candidates
        ):
            raise IdentityAttackContractError("forest depth candidates must be positive or None")
        if self.n_estimators < 1 or self.min_samples_leaf < 1:
            raise IdentityAttackContractError("forest size parameters must be positive")
        training.validate(name="training")
        validation.validate(name="validation")
        scored: list[tuple[float, int, int | None]] = []
        for depth in self.depth_candidates:
            model = self._new_model(depth)
            model.fit(training.features, training.labels.astype(str))
            predicted = model.predict(validation.features)
            score = float(balanced_accuracy_score(validation.labels.astype(str), predicted))
            complexity = depth if depth is not None else 2**31
            scored.append((score, -complexity, depth))
        _, _, self.selected_depth = max(scored, key=lambda item: (item[0], item[1]))
        self._model = self._new_model(self.selected_depth)
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

    def _new_model(self, depth: int | None) -> RandomForestClassifier:
        return RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=depth,
            min_samples_leaf=self.min_samples_leaf,
            random_state=self.seed,
            n_jobs=1,
        )

