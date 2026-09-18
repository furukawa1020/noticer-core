from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
)
from noticer_core.evaluation.shared_comparison_fixture import (
    PublicAction,
    SharedComparisonFixture,
    SharedFixtureError,
    SyntheticScenario,
    bind_shared_fixture,
    shared_contract_for_fixture,
)


def _fixture() -> SharedComparisonFixture:
    return SharedComparisonFixture(
        "noticer.k7.shared-comparison-fixture.v1",
        "synthetic-matched-action-1",
        ("hint",),
        (PublicAction("notify", "service-a", 2),),
        (True, True, True),
        (
            SyntheticScenario("left", False, (0,),
                              ((False,), (False,), (False,))),
            SyntheticScenario("right", True, (1,),
                              ((True,), (True,), (True,))),
        ),
    )


def _manifest(fixture: SharedComparisonFixture) -> ComparisonManifest:
    mechanisms = tuple(
        Mechanism(
            name,
            "approximation" if name in {"automata", "netshaper_like", "pacer_like"}
            else "local",
            "notion-" + name, "source-" + name, "v1",
            ("a" * 64,), "a" * 64,
        )
        for name in sorted(MECHANISMS)
    )
    return ComparisonManifest(
        "noticer.k7.baseline-comparison.v1",
        shared_contract_for_fixture(fixture),
        mechanisms, AXES, True,
    )


def test_all_six_digests_are_stable_for_one_fixture() -> None:
    fixture = _fixture()
    assert shared_contract_for_fixture(fixture) == shared_contract_for_fixture(_fixture())
    bind_shared_fixture(_manifest(fixture), fixture)


def test_private_readiness_does_not_change_public_utility_digest() -> None:
    original = _fixture()
    changed = replace(
        original,
        scenarios=(
            original.scenarios[0],
            replace(original.scenarios[1], private_ready_slots=(2,)),
        ),
    )
    a = shared_contract_for_fixture(original)
    b = shared_contract_for_fixture(changed)
    assert a.utility_sha256 == b.utility_sha256
    assert a.corpus_sha256 != b.corpus_sha256
    assert a.case_sha256 != b.case_sha256


def test_each_shared_binding_rejects_substitution() -> None:
    fixture = _fixture()
    manifest = _manifest(fixture)
    for field in (
        "case_sha256", "observer_sha256", "utility_sha256",
        "fault_trace_sha256", "cost_sha256", "corpus_sha256",
    ):
        tampered = replace(
            manifest, shared=replace(manifest.shared, **{field: "f" * 64})
        )
        with pytest.raises(SharedFixtureError) as caught:
            bind_shared_fixture(tampered, fixture)
        assert caught.value.category == f"{field}_mismatch"


def test_unmatched_or_noncanonical_scenarios_fail_closed() -> None:
    fixture = _fixture()
    invalid = replace(
        fixture,
        scenarios=(
            fixture.scenarios[0],
            replace(fixture.scenarios[1], private_ready_slots=(3,)),
        ),
    )
    with pytest.raises(SharedFixtureError) as caught:
        shared_contract_for_fixture(invalid)
    assert caught.value.category == "invalid_scenarios"
