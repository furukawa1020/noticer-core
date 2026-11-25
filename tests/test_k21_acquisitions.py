import pytest

from noticer_core.evaluation.k21_acquisitions import (
    RecordingEntry,
    assess_acquisition_eligibility,
)


def test_window_exports_and_unknown_boundaries_do_not_create_independent_sessions() -> None:
    rows = [RecordingEntry("p1", "a1", True)] * 50
    rows += [RecordingEntry("p1", "a2", False), RecordingEntry("p2", "a3", True)]
    actual = assess_acquisition_eligibility(rows, minimum_per_participant=2)
    assert actual.confirmed_acquisitions == 2
    assert actual.unconfirmed_acquisitions == 1
    assert not actual.eligible


def test_conflicting_group_provenance_is_invalid() -> None:
    with pytest.raises(ValueError, match="conflicting"):
        assess_acquisition_eligibility(
            [RecordingEntry("p1", "a1", True), RecordingEntry("p2", "a1", False)],
            minimum_per_participant=2,
        )
