from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_status import audit_public_futures


def test_cutoff_and_invalid_budget_are_not_verified():
    left, right = crossed_public_futures()
    assert audit_public_futures(left, right).status == "verified"
    cutoff = audit_public_futures(left, right, max_candidates=3)
    assert cutoff.status == "inconclusive"
    assert cutoff.evidence is None
    invalid = audit_public_futures(left, right, max_candidates=0)
    assert invalid.status == "invalid"
    assert invalid.evidence is None
