import pytest

from noticer_core.evaluation.k21_exclusion import Exclusion, summarize_exclusions


def test_reasons_keep_quality_and_withdrawal_separate() -> None:
    summary = summarize_exclusions(
        {"a": None, "b": Exclusion.SIGNAL_QUALITY, "c": Exclusion.CONSENT_WITHDRAWN},
        permitted=set(Exclusion),
    )
    assert summary.candidates == 3 and summary.retained == 1
    assert dict(summary.excluded_by_reason)[Exclusion.CONSENT_WITHDRAWN] == 1


def test_unregistered_reason_is_rejected() -> None:
    with pytest.raises(ValueError, match="preregistered"):
        summarize_exclusions({"a": Exclusion.SIGNAL_QUALITY}, permitted=set())
