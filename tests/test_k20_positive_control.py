from __future__ import annotations

import numpy as np
import pytest

from noticer_core.data.k20_positive_control import (
    PositiveControlConfig,
    centroid_separation_ratio,
    generate_positive_control,
)


def test_positive_control_is_deterministic_and_session_rich() -> None:
    config = PositiveControlConfig()
    first = generate_positive_control(config, seed=2027)
    second = generate_positive_control(config, seed=2027)
    np.testing.assert_array_equal(first.features, second.features)
    assert first.n_subjects == config.subjects
    assert first.n_sessions == config.subjects * config.sessions_per_subject
    first.require_sessions_per_subject(3)


def test_positive_control_contains_strong_identity_structure() -> None:
    dataset = generate_positive_control(seed=7)
    assert centroid_separation_ratio(dataset) > 3.0


def test_seed_changes_realization_without_changing_contract() -> None:
    first = generate_positive_control(seed=1)
    second = generate_positive_control(seed=2)
    assert first.features.shape == second.features.shape
    assert first.feature_names == second.feature_names
    assert not np.array_equal(first.features, second.features)


@pytest.mark.parametrize(
    "config",
    [
        PositiveControlConfig(subjects=2),
        PositiveControlConfig(sessions_per_subject=2),
        PositiveControlConfig(identity_strength=0),
        PositiveControlConfig(noise=-1),
    ],
)
def test_invalid_positive_control_configuration_is_rejected(
    config: PositiveControlConfig,
) -> None:
    with pytest.raises(ValueError):
        generate_positive_control(config, seed=1)
