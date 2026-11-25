import pytest

from noticer_core.evaluation.k20_effect import assess_effect, paired_effect


def test_paired_reduction_is_positive_and_keeps_original_units() -> None:
    effect = paired_effect({"b": 10, "a": 7}, {"a": 5, "b": 6}, lower_is_better=True)
    assert effect.pair_ids == ("a", "b")
    assert effect.improvements == (2, 4)
    assert effect.mean_improvement == 3


def test_mismatched_pairs_cannot_be_silently_omitted() -> None:
    with pytest.raises(ValueError, match="exactly matched"):
        paired_effect({"a": 2}, {"b": 2}, lower_is_better=False)


def test_meaningful_effect_depends_on_interval() -> None:
    assert assess_effect(2, 3, meaningful=2) == "meaningful"
    assert assess_effect(0, 3, meaningful=2) == "inconclusive"
    assert assess_effect(0, 1, meaningful=2) == "below-threshold"
