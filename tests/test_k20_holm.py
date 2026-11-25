import pytest

from noticer_core.evaluation.k20_holm import holm_adjust


def test_holm_cumulative_max_and_report_order() -> None:
    corrected = holm_adjust(("c", "b", "a"), {"a": 0.01, "b": 0.04, "c": 0.05})
    assert [row.name for row in corrected] == ["c", "b", "a"]
    assert [row.adjusted_p for row in corrected] == pytest.approx([0.08, 0.08, 0.03])
    assert [row.reject for row in corrected] == [False, False, True]


def test_missing_p_value_fails_closed() -> None:
    with pytest.raises(ValueError, match="exact declared"):
        holm_adjust(("a", "b"), {"a": 0.001})
