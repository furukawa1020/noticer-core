from dataclasses import replace

from noticer_core.recovery_claim_scope import RecoveryEvidence, allows_bounded_synthetic_claim
from noticer_core.recovery_verdict import Resolution


def test_synthetic_claim_requires_nonvacuous_full_utility_and_binding() -> None:
    complete = RecoveryEvidence(Resolution.VERIFIED, True, 8, 8, 0)
    assert allows_bounded_synthetic_claim(complete)
    assert not allows_bounded_synthetic_claim(replace(complete, bound_receipts=False))
    assert not allows_bounded_synthetic_claim(replace(complete, on_time_exactly_once=4))
    assert not allows_bounded_synthetic_claim(replace(complete, unauthorized_receipts=1))
    assert not allows_bounded_synthetic_claim(
        replace(complete, resolution=Resolution.INCONCLUSIVE)
    )
    assert not allows_bounded_synthetic_claim(
        replace(complete, expected_actions=0, on_time_exactly_once=0)
    )
