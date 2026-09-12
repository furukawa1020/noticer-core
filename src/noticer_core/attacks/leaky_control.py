"""Separated leaky controls for the K7 adaptive attack matrix."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import roc_auc_score

from noticer_core.attacks.adaptive import (
    AdaptiveAttackDataset,
    AdaptiveAttackPrediction,
    ModelFamily,
    ObserverFamily,
)


class LeakyControlError(ValueError):
    """Raised when a control can be confused with protected evidence."""


@dataclass(frozen=True)
class LeakyControl:
    control_id: str
    artifact_namespace: str
    source_dataset_sha256: str
    dataset: AdaptiveAttackDataset
    is_control: bool = True


@dataclass(frozen=True)
class LeakyControlReport:
    detected: bool
    minimum_auc: float
    auc_by_attacker: dict[str, float]
    failed_attackers: tuple[str, ...]


def build_leaky_control(
    dataset: AdaptiveAttackDataset,
    *,
    source_dataset_sha256: str,
    amplitude: float,
) -> LeakyControl:
    """Inject an explicit side-label channel into every observer view."""
    if len(source_dataset_sha256) != 64 or any(
        character not in "0123456789abcdef"
        for character in source_dataset_sha256
    ):
        raise LeakyControlError("source dataset digest must be SHA-256")
    if not np.isfinite(amplitude) or amplitude <= 0:
        raise LeakyControlError("control amplitude must be positive")
    signed = dataset.labels.astype(float) * (2.0 * amplitude) - amplitude
    views: dict[ObserverFamily, np.ndarray] = {}
    for observer, values in dataset.views.items():
        controlled = values.astype(float, copy=True)
        if controlled.ndim == 2:
            controlled[:, 0] = signed
        elif controlled.ndim == 3:
            controlled[:, :, 0] = signed[:, np.newaxis]
        else:
            raise LeakyControlError(f"unsupported observer rank: {observer.value}")
        views[observer] = controlled
    controlled_dataset = AdaptiveAttackDataset(
        labels=dataset.labels.copy(),
        pair_ids=dataset.pair_ids.copy(),
        family_ids=dataset.family_ids.copy(),
        session_ids=dataset.session_ids.copy(),
        views=views,
    )
    return LeakyControl(
        control_id="explicit-private-side-channel-v1",
        artifact_namespace="controls/k7_adaptive",
        source_dataset_sha256=source_dataset_sha256,
        dataset=controlled_dataset,
    )


def evaluate_leaky_control(
    predictions: tuple[AdaptiveAttackPrediction, ...],
    *,
    minimum_auc: float,
) -> LeakyControlReport:
    """Require every pre-registered attacker to detect its control."""
    if not 0.5 < minimum_auc <= 1.0:
        raise LeakyControlError("minimum AUC must be in (0.5, 1.0]")
    expected = {
        (observer, model) for observer in ObserverFamily for model in ModelFamily
    }
    indexed = {(item.observer, item.model): item for item in predictions}
    if set(indexed) != expected:
        raise LeakyControlError("complete attack matrix required for control")
    auc_by_attacker = {
        f"{observer.value}/{model.value}": float(
            roc_auc_score(
                indexed[(observer, model)].truth,
                indexed[(observer, model)].scores,
            )
        )
        for observer, model in sorted(
            expected,
            key=lambda value: (value[0].value, value[1].value),
        )
    }
    failed = tuple(
        attacker
        for attacker, auc in auc_by_attacker.items()
        if auc < minimum_auc
    )
    return LeakyControlReport(
        detected=not failed,
        minimum_auc=minimum_auc,
        auc_by_attacker=auc_by_attacker,
        failed_attackers=failed,
    )
