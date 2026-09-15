from dataclasses import replace

import pytest

from noticer_core.evaluation.public_handoff import (
    PublicHandoffContract,
    PublicHandoffState,
    ResourceBounds,
)
from noticer_core.evaluation.two_component_composition import (
    CertifiedBucket,
    CompositionError,
    SourceVerdict,
    compose_two,
    composition_digest,
    independently_check_bounds,
)


def _contract(incoming: bool) -> PublicHandoffContract:
    return PublicHandoffContract(
        "noticer.k7.public-handoff.v1", "right" if incoming else "left",
        "a" * 64, "b" * 64, ("d" if incoming else "c") * 64,
        PublicHandoffState("e" * 64, ("alpha", "beta"), "epoch", "key",
                           0 if incoming else 5),
        ResourceBounds(7 if incoming else 5, 20 if incoming else 10, 2, 1),
    )


def _bucket(incoming: bool) -> CertifiedBucket:
    return CertifiedBucket(_contract(incoming), SourceVerdict.VERIFIED,
                           SourceVerdict.VERIFIED)


def test_verified_compatible_pair_composes_additive_finite_bounds() -> None:
    left, right = _bucket(False), _bucket(True)
    result = compose_two(left, right)
    assert result.composed_bounds == ResourceBounds(12, 30, 4, 2)
    assert independently_check_bounds(result, left.contract, right.contract)
    assert result.proof_status == "DERIVED_CANDIDATE"
    assert not result.security_proof
    assert composition_digest(result) == composition_digest(compose_two(left, right))


@pytest.mark.parametrize("side,field", [
    ("left", "aqni_verdict"), ("left", "utility_verdict"),
    ("right", "aqni_verdict"), ("right", "utility_verdict"),
])
def test_every_unverified_source_dimension_is_rejected(side: str, field: str) -> None:
    left, right = _bucket(False), _bucket(True)
    target = left if side == "left" else right
    changed = replace(target, **{field: SourceVerdict.INCONCLUSIVE})
    with pytest.raises(CompositionError) as caught:
        compose_two(changed if side == "left" else left,
                    changed if side == "right" else right)
    assert caught.value.category == f"{side}_{field.removesuffix('_verdict')}_not_verified"


def test_incompatible_pair_never_composes() -> None:
    left, right = _bucket(False), _bucket(True)
    bad = replace(right, contract=replace(right.contract,
                  observer_contract_sha256="f" * 64))
    with pytest.raises(CompositionError) as caught:
        compose_two(left, bad)
    assert caught.value.category == "incompatible_handoff:observer_contract"


def test_independent_bound_oracle_detects_tampering() -> None:
    left, right = _bucket(False), _bucket(True)
    result = compose_two(left, right)
    tampered = replace(result, composed_bounds=ResourceBounds(11, 30, 4, 2))
    assert not independently_check_bounds(tampered, left.contract, right.contract)
