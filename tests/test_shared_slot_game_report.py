from noticer_core.shared_slot_game_report import build_checked_game_report


def test_checked_report_has_policy_negative_proof_and_non_evidence_controls():
    report = build_checked_game_report()
    games = report["scenarios"]
    hedge = games["robust_hedge"]
    assert hedge["status"] == "verified_policy"
    assert hedge["causal"] == hedge["offline"] == (3, 3)
    assert hedge["deadline_first"] == (3, 2)
    for game in ("late_conflict", "crossed_futures"):
        assert games[game]["status"] == "verified_no_policy"
    absent = games["late_conflict"]
    assert absent["offline"] == (3, 3)
    assert absent["certificate"]["slot"] == 0
    assert report["controls"] == {"forced_cutoff": "inconclusive", "invalid_budget": "invalid"}
