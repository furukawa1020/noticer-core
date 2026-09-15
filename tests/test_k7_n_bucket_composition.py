from dataclasses import replace

import pytest

from noticer_core.evaluation.n_bucket_composition import (
    LongitudinalBucket,
    compose_n,
    independently_check_n,
    n_certificate_digest,
)
from noticer_core.evaluation.public_handoff import (
    PublicHandoffContract,
    PublicHandoffState,
    ResourceBounds,
)
from noticer_core.evaluation.two_component_composition import (
    CompositionError,
    SourceVerdict,
)


def _edge(source: str, *, incoming: bool, boundary: int) -> PublicHandoffContract:
    bounds = ResourceBounds(boundary + 2, 10, 1, 1)
    return PublicHandoffContract(
        "noticer.k7.public-handoff.v1",
        f"{source}-{'in' if incoming else 'out'}",
        "a" * 64,
        "b" * 64,
        source,
        PublicHandoffState(
            "e" * 64, ("alpha", "beta"), "epoch", "key",
            0 if incoming else bounds.horizon_slots,
        ),
        bounds,
    )


def _bucket(index: int, count: int) -> LongitudinalBucket:
    source = str(index + 1) * 64
    bounds = ResourceBounds(index + 2, 10, 1, 1)
    incoming = _edge(source, incoming=True, boundary=index) if index > 0 else None
    outgoing = (
        _edge(source, incoming=False, boundary=index) if index + 1 < count else None
    )
    return LongitudinalBucket(
        f"bucket-{index}", source, bounds, SourceVerdict.VERIFIED,
        SourceVerdict.VERIFIED, incoming, outgoing,
    )


@pytest.mark.parametrize("count", [1, 2, 4])
def test_induction_handles_base_pair_and_n_cases(count: int) -> None:
    buckets = tuple(_bucket(i, count) for i in range(count))
    result = compose_n(buckets)
    assert result.induction_steps == count - 1
    assert len(result.boundary_witness_sha256) == count - 1
    assert result.composed_bounds.horizon_slots == sum(range(2, count + 2))
    assert independently_check_n(result, buckets)
    assert not result.security_proof
    assert n_certificate_digest(result) == n_certificate_digest(compose_n(buckets))


def test_missing_middle_boundary_and_unverified_bucket_fail_closed() -> None:
    buckets = tuple(_bucket(i, 3) for i in range(3))
    missing = (buckets[0], replace(buckets[1], incoming=None), buckets[2])
    with pytest.raises(CompositionError) as caught:
        compose_n(missing)
    assert caught.value.category == "bucket_1_missing_incoming"
    unverified = (
        buckets[0],
        replace(buckets[1], aqni_verdict=SourceVerdict.INCONCLUSIVE),
        buckets[2],
    )
    with pytest.raises(CompositionError) as caught:
        compose_n(unverified)
    assert caught.value.category == "bucket_1_aqni_not_verified"


def test_reordering_and_certificate_substitution_are_detected() -> None:
    buckets = tuple(_bucket(i, 3) for i in range(3))
    result = compose_n(buckets)
    assert not independently_check_n(result, (buckets[1], buckets[0], buckets[2]))
    substituted = replace(
        buckets[1], source_certificate_sha256="f" * 64
    )
    with pytest.raises(CompositionError) as caught:
        compose_n((buckets[0], substituted, buckets[2]))
    assert "source_mismatch" in caught.value.category


def test_boundary_mismatch_has_indexed_reason() -> None:
    buckets = list(_bucket(i, 2) for i in range(2))
    assert buckets[1].incoming is not None
    bad_state = replace(buckets[1].incoming.state, epoch_id="other")
    buckets[1] = replace(
        buckets[1], incoming=replace(buckets[1].incoming, state=bad_state)
    )
    with pytest.raises(CompositionError) as caught:
        compose_n(tuple(buckets))
    assert caught.value.category == "boundary_0_incompatible:epoch"
