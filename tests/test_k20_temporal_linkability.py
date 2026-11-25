from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_temporal_linkability import (
    LinkabilitySplit,
    TemporalLinkabilityError,
    run_temporal_linkability_attack,
)
from noticer_core.data.k20_positive_control import (
    PositiveControlConfig,
    generate_positive_control,
)


def inputs() -> tuple[object, LinkabilitySplit]:
    dataset = generate_positive_control(
        PositiveControlConfig(subjects=4, sessions_per_subject=6, windows_per_session=12), seed=4
    )
    groups: list[list[str]] = [[], [], []]
    for subject in sorted(np.unique(dataset.subject_ids.astype(str))):
        sessions = sorted(
            np.unique(dataset.session_ids[dataset.subject_ids == subject]).astype(str)
        )
        groups[0].extend(sessions[:2])
        groups[1].extend(sessions[2:4])
        groups[2].extend(sessions[4:])
    return dataset, LinkabilitySplit(*(tuple(values) for values in groups))


def test_temporal_attack_links_identity_positive_sessions() -> None:
    dataset, split = inputs()
    result = run_temporal_linkability_attack(
        dataset, split, regularization_candidates=(0.1, 1.0, 10.0), seed=9
    )
    assert result.roc_auc > 0.9
    assert result.selected_c in (0.1, 1.0, 10.0)
    assert len(result.truth) == len(result.left_sessions) == len(result.right_sessions)


def test_temporal_attack_is_reproducible() -> None:
    dataset, split = inputs()
    first = run_temporal_linkability_attack(
        dataset, split, regularization_candidates=(1.0,), seed=9
    )
    second = run_temporal_linkability_attack(
        dataset, split, regularization_candidates=(1.0,), seed=9
    )
    np.testing.assert_array_equal(first.scores, second.scores)


def test_session_overlap_is_rejected() -> None:
    dataset, split = inputs()
    invalid = LinkabilitySplit(
        split.train_sessions,
        split.validation_sessions,
        split.test_sessions + (split.train_sessions[0],),
    )
    with pytest.raises(TemporalLinkabilityError, match="disjoint"):
        run_temporal_linkability_attack(dataset, invalid, regularization_candidates=(1.0,), seed=9)


def test_incomplete_session_coverage_is_rejected() -> None:
    dataset, split = inputs()
    invalid = LinkabilitySplit(
        split.train_sessions[:-1], split.validation_sessions, split.test_sessions
    )
    with pytest.raises(TemporalLinkabilityError, match="cover every"):
        run_temporal_linkability_attack(dataset, invalid, regularization_candidates=(1.0,), seed=9)
