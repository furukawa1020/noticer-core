import numpy as np
import pytest

from noticer_core.evaluation.k20_calibration import evaluate_calibration


def test_fixed_bins_and_multiclass_brier() -> None:
    result = evaluate_calibration(
        np.array([[1, 0, 0], [0.2, 0.6, 0.2]]), np.array([0, 2]), bins=2
    )
    assert result.bin_counts == (0, 2)
    assert result.brier == pytest.approx(0.52)
    assert result.log_loss == pytest.approx(-np.log(0.2) / 2)
    assert result.top_label_ece == pytest.approx(0.3)


@pytest.mark.parametrize("truth", [np.array([0.5]), np.array([2]), np.array([True])])
def test_invalid_truth_is_not_coerced(truth: np.ndarray) -> None:
    with pytest.raises(ValueError, match="truth"):
        evaluate_calibration(np.array([[0.8, 0.2]]), truth)
