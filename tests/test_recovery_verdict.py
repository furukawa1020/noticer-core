from noticer_core.recovery_verdict import Resolution, resolve_checkers


def report(status: str) -> dict:
    return dict.fromkeys((
        "category", "slot", "observer", "side", "causal_field",
        "obligation", "action", "reason",
    )) | {"status": status, "checked_horizon": 2}


def test_a_single_positive_or_incomplete_verdict_cannot_promote() -> None:
    verified = report("verified")
    assert resolve_checkers(verified, verified) is Resolution.VERIFIED
    assert resolve_checkers(verified, report("inconclusive")) is Resolution.UNRESOLVED
    assert resolve_checkers({"status": "verified"}, {"status": "verified"}) is Resolution.UNRESOLVED


def test_agreeing_resource_cutoffs_stay_inconclusive() -> None:
    cutoff = report("inconclusive") | {"reason": "node_limit", "checked_horizon": None}
    assert resolve_checkers(cutoff, cutoff) is Resolution.INCONCLUSIVE
