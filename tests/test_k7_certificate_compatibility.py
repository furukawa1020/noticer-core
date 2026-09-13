from dataclasses import replace

from noticer_core.evaluation.certificate_compatibility import (
    CompatibilityDecision,
    canonical_witness_json,
    check_compatibility,
    witness_digest,
)
from noticer_core.evaluation.public_handoff import (
    PublicHandoffContract,
    PublicHandoffState,
    ResourceBounds,
)


def _contract(*, incoming: bool) -> PublicHandoffContract:
    return PublicHandoffContract(
        format_version="noticer.k7.public-handoff.v1",
        contract_id="right" if incoming else "left",
        action_semantics_sha256="a" * 64,
        observer_contract_sha256="b" * 64,
        source_certificate_sha256=("d" if incoming else "c") * 64,
        state=PublicHandoffState(
            observer_state_sha256="e" * 64,
            colluding_services=("alpha", "beta"),
            epoch_id="epoch-8",
            key_epoch_id="key-epoch-8",
            epoch_event_slot=0 if incoming else 5,
        ),
        bounds=ResourceBounds(7 if incoming else 5, 64, 2, 1),
    )


def test_compatible_boundary_emits_deterministic_nonproof_witness() -> None:
    first = check_compatibility(_contract(incoming=False), _contract(incoming=True))
    second = check_compatibility(_contract(incoming=False), _contract(incoming=True))
    assert first == second
    assert first.decision is CompatibilityDecision.COMPATIBLE
    assert not first.mismatch_reasons
    assert not first.security_proof
    assert witness_digest(first) == witness_digest(second)
    assert canonical_witness_json(first).endswith(b"\n")


def test_each_public_boundary_mismatch_is_rejected_with_reason() -> None:
    left = _contract(incoming=False)
    right = _contract(incoming=True)
    cases = {
        "action_semantics": replace(right, action_semantics_sha256="f" * 64),
        "observer_contract": replace(right, observer_contract_sha256="f" * 64),
        "observer_state": replace(
            right, state=replace(right.state, observer_state_sha256="f" * 64)
        ),
        "service_collusion": replace(
            right, state=replace(right.state, colluding_services=("alpha",))
        ),
        "epoch": replace(right, state=replace(right.state, epoch_id="epoch-9")),
        "key_epoch": replace(
            right, state=replace(right.state, key_epoch_id="key-epoch-9")
        ),
    }
    for reason, candidate in cases.items():
        witness = check_compatibility(left, candidate)
        assert witness.decision is CompatibilityDecision.INCOMPATIBLE
        assert reason in witness.mismatch_reasons


def test_left_end_and_right_start_are_resource_boundaries() -> None:
    left = _contract(incoming=False)
    right = _contract(incoming=True)
    bad_left = replace(left, state=replace(left.state, epoch_event_slot=4))
    bad_right = replace(right, state=replace(right.state, epoch_event_slot=1))
    assert "left_boundary_slot" in check_compatibility(
        bad_left, right
    ).mismatch_reasons
    assert "right_boundary_slot" in check_compatibility(
        left, bad_right
    ).mismatch_reasons


def test_certificate_digest_substitution_changes_witness_binding() -> None:
    left = _contract(incoming=False)
    right = _contract(incoming=True)
    original = check_compatibility(left, right)
    substituted = check_compatibility(
        left, replace(right, source_certificate_sha256="f" * 64)
    )
    assert substituted.decision is CompatibilityDecision.COMPATIBLE
    assert original.right_contract_sha256 != substituted.right_contract_sha256
    assert witness_digest(original) != witness_digest(substituted)
