import json

from noticer_core.shared_slot_report import build_shared_slot_report


def test_synthetic_report_keeps_tie_deficit_and_cutoff_together():
    report = build_shared_slot_report()
    schedule = report["schedules"]
    assert len(schedule["deadline_gap"]["deadline_first"]) == 2
    assert len(schedule["deadline_gap"]["exact_offline"]) == 3
    assert schedule["no_contention"]["deadline_first"] == schedule["no_contention"]["exact_offline"]
    assert schedule["capacity_deficit"]["deficit"]["capacity"] == 1
    causality = report["causality"]
    assert causality["randomized_first_choice"] == "1/2"
    assert causality["controls"]["forced_cutoff"] == "inconclusive"
    assert causality["controls"]["invalid_budget"] == "invalid"
    first = causality["shortest_trace"]
    assert len(first) == 1 and first[0]["slot"] == 0
    assert first[0]["left_state"] != first[0]["right_state"]
    assert json.dumps(report, sort_keys=True) == json.dumps(
        build_shared_slot_report(), sort_keys=True
    )
