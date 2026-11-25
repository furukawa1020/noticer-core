import pytest

from noticer_core.evaluation.k20_utility import assess_utility


@pytest.mark.parametrize(
    ("interval", "verdict"),
    [
        ((-0.01, 0.03), "noninferior"),
        ((-0.10, -0.06), "inferior"),
        ((-0.05, 0.02), "inconclusive"),
        (None, "inconclusive"),
    ],
)
def test_interval_gate(interval: tuple[float, float] | None, verdict: str) -> None:
    assert assess_utility(interval, margin=0.05, semantics_match=True) == verdict


def test_action_mismatch_cannot_be_offset_by_positive_utility() -> None:
    assert assess_utility((1, 2), margin=0.05, semantics_match=False) == "action-mismatch"
