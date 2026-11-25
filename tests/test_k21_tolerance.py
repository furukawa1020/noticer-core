import pytest

from noticer_core.evaluation.k21_tolerance import FloatTolerance, compare_replay


def test_only_designated_float_fields_can_differ() -> None:
    original = {"count": 5, "digest": "sha-a", "mean": 0.25}
    replay = {"count": 5.0, "digest": "sha-b", "mean": 0.2500001}
    assert compare_replay(original, replay, {"mean": FloatTolerance(1e-6, 0)}) == (
        "count", "digest"
    )


def test_float_without_predeclared_tolerance_is_invalid() -> None:
    with pytest.raises(ValueError, match="tolerances"):
        compare_replay({"mean": 0.25}, {"mean": 0.25}, {})
