from __future__ import annotations

import numpy as np
import pytest

from noticer_core.evaluation.k20_linkability_metrics import (
    LinkabilityMetricError,
    cross_session_linkability_metrics,
)


def test_perfect_linkability_has_maximum_advantage() -> None:
    result = cross_session_linkability_metrics(
        np.asarray([0, 0, 1, 1]),
        np.asarray([0.1, 0.2, 0.8, 0.9]),
        fpr_limit=0,
    )
    assert result.roc_auc == 1.0
    assert result.average_precision == 1.0
    assert result.equal_error_rate == 0.0
    assert result.tpr_at_fpr == 1.0
    assert result.advantage == 1.0


def test_low_nonzero_fpr_budget_below_resolution_is_unavailable() -> None:
    result = cross_session_linkability_metrics(
        np.asarray([0, 0, 1, 1]), np.asarray([0.1, 0.2, 0.8, 0.9]), fpr_limit=0.01
    )
    assert result.fpr_resolution == 0.5
    assert result.tpr_at_fpr is None


def test_reversed_scores_still_expose_absolute_advantage() -> None:
    result = cross_session_linkability_metrics(
        np.asarray([0, 0, 1, 1]), np.asarray([0.9, 0.8, 0.2, 0.1])
    )
    assert result.roc_auc == 0.0
    assert result.advantage == 1.0


@pytest.mark.parametrize(
    ("truth", "scores", "message"),
    [
        (np.asarray([1, 1]), np.asarray([0.8, 0.9]), "zero and one"),
        (np.asarray([0.9, 1.1]), np.asarray([0.8, 0.9]), "zero and one"),
        (np.asarray([0, 1]), np.asarray([0.1]), "aligned"),
        (np.asarray([0, 1]), np.asarray([0.1, np.nan]), "finite"),
    ],
)
def test_invalid_metric_inputs_fail_closed(
    truth: np.ndarray, scores: np.ndarray, message: str
) -> None:
    with pytest.raises(LinkabilityMetricError, match=message):
        cross_session_linkability_metrics(truth, scores)


def test_invalid_fpr_limit_is_rejected() -> None:
    with pytest.raises(LinkabilityMetricError, match="fpr_limit"):
        cross_session_linkability_metrics(
            np.asarray([0, 1]), np.asarray([0.1, 0.9]), fpr_limit=1.1
        )
