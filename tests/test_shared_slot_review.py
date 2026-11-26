import json

from noticer_core.shared_slot_review import build_anonymous_evidence


def test_standalone_fixture_does_not_emit_project_or_run_metadata():
    fixture = build_anonymous_evidence()
    assert set(fixture) == {"schema", "empirical", "schedules", "first_choice"}
    assert fixture["empirical"] is False
    assert "noticer" not in json.dumps(fixture).lower()
