import pytest

from noticer_core.evaluation.k20_claim_gate import (
    CheckState,
    ClaimGate,
    ClaimVerdict,
    decide_claim,
)
from noticer_core.evaluation.k20_dataset_manifest import DatasetManifest, EvidenceClass


def manifest(*, fixture: bool = False) -> DatasetManifest:
    return DatasetManifest(
        "example-v1",
        EvidenceClass.FIXTURE if fixture else EvidenceClass.REGISTERED_EXPERIMENT,
        "a" * 64, "b" * 64, 5, 15, 150, "example", False, False,
        None if fixture else "protocol-v1",
    )


@pytest.mark.parametrize(
    ("state", "verdict"),
    [
        (CheckState.PASS, ClaimVerdict.VERIFIED),
        (CheckState.FAILED, ClaimVerdict.FAILED),
        (CheckState.INVALID, ClaimVerdict.INVALID),
        (CheckState.INCONCLUSIVE, ClaimVerdict.INCONCLUSIVE),
    ],
)
def test_fail_closed_check_combination(state: CheckState, verdict: ClaimVerdict) -> None:
    checks = dict.fromkeys(ClaimGate, CheckState.PASS)
    checks[ClaimGate.VALID_CONTROLS] = state
    assert decide_claim(manifest(), checks).verdict is verdict


def test_missing_check_cannot_be_treated_as_a_pass() -> None:
    result = decide_claim(manifest(), {})
    assert result.verdict is ClaimVerdict.INCONCLUSIVE
    assert result.missing == tuple(ClaimGate)


def test_fixture_cannot_authorize_a_confirmatory_claim() -> None:
    checks = dict.fromkeys(ClaimGate, CheckState.PASS)
    assert decide_claim(manifest(fixture=True), checks).verdict is ClaimVerdict.INCONCLUSIVE
