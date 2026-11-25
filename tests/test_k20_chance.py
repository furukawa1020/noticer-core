import pytest

from noticer_core.evaluation.k20_chance import assess_chance


def test_chance_requires_full_interval_within_margin() -> None:
    assert assess_chance({"a": 0.5}, chance=0.5, margin=0.1).verdict == "inconclusive"
    sparse = {str(i): 0.5 for i in range(5)}
    assert assess_chance(sparse, chance=0.5, margin=0.1).verdict == "inconclusive"
    dense = {str(i): 0.5 for i in range(400)}
    assert assess_chance(dense, chance=0.5, margin=0.1).verdict == "chance-equivalent"


@pytest.mark.parametrize("score", [0.1, 0.9])
def test_detects_departures_in_either_direction(score: float) -> None:
    scores = {str(i): score for i in range(400)}
    assert assess_chance(scores, chance=0.5, margin=0.1).verdict == "outside-chance-band"


def test_rejects_nonfinite_scores() -> None:
    with pytest.raises(ValueError, match="finite score"):
        assess_chance({"a": float("nan")}, chance=0.5, margin=0.1)
