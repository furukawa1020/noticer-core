"""Bind narrow synthetic claims to checked projection evidence without scope promotion."""

from dataclasses import dataclass

from noticer_core.recovery_verdict import Resolution


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    resolution: Resolution
    bound_receipts: bool
    expected_actions: int
    on_time_exactly_once: int
    unauthorized_receipts: int


def allows_bounded_synthetic_claim(evidence: RecoveryEvidence) -> bool:
    if any(
        type(value) is not int or value < 0 for value in (
            evidence.expected_actions, evidence.on_time_exactly_once,
            evidence.unauthorized_receipts,
        )
    ):
        raise ValueError("claim counts must be nonnegative integers")
    if evidence.on_time_exactly_once > evidence.expected_actions:
        raise ValueError("count cannot exceed the declared obligation inventory")
    return (
        evidence.resolution is Resolution.VERIFIED
        and evidence.bound_receipts is True
        and evidence.expected_actions > 0
        and evidence.on_time_exactly_once == evidence.expected_actions
        and evidence.unauthorized_receipts == 0
    )
