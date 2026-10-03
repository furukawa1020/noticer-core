from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
)
from noticer_core.evaluation.netshaper_like import (
    NetShaperLikeConfig,
    run_netshaper_like,
)
from noticer_core.evaluation.netshaper_like import (
    config_digest as netshaper_digest,
)
from noticer_core.evaluation.network_baseline_fixture import (
    NetworkBaselineFixtureError,
    prepare_shared_network_baseline,
)
from noticer_core.evaluation.pacer_like import (
    PacerLikeConfig,
    run_pacer_like,
    utility_trace_digest,
)
from noticer_core.evaluation.pacer_like import (
    config_digest as pacer_digest,
)
from noticer_core.evaluation.shared_comparison_fixture import (
    FORMAT_VERSION,
    PublicAction,
    SharedComparisonFixture,
    SharedFixtureError,
    SyntheticScenario,
    shared_contract_for_fixture,
)


def _fixture() -> SharedComparisonFixture:
    return SharedComparisonFixture(
        FORMAT_VERSION,
        "network-baseline-shared-case",
        ("hint",),
        (PublicAction("notify", "service-a", 3),),
        (True, False, True, True),
        (
            SyntheticScenario(
                "left",
                False,
                (0,),
                ((False,), (False,), (False,), (False,)),
            ),
            SyntheticScenario(
                "right",
                True,
                (1,),
                ((True,), (True,), (True,), (True,)),
            ),
        ),
    )


def _manifest(
    fixture: SharedComparisonFixture,
    pacer: PacerLikeConfig,
    netshaper: NetShaperLikeConfig,
) -> ComparisonManifest:
    mechanisms = []
    for name in sorted(MECHANISMS):
        digest = (
            pacer_digest(pacer)
            if name == "pacer_like"
            else netshaper_digest(netshaper)
            if name == "netshaper_like"
            else "c" * 64
        )
        mechanisms.append(
            Mechanism(
                name,
                "approximation"
                if name in {"automata", "netshaper_like", "pacer_like"}
                else "local",
                "notion-" + name,
                "source-" + name,
                "v1",
                (digest,),
                digest,
            )
        )
    return ComparisonManifest(
        "noticer.k7.baseline-comparison.v1",
        shared_contract_for_fixture(fixture),
        tuple(mechanisms),
        AXES,
        True,
    )


def test_both_network_baselines_consume_one_prepared_scenario() -> None:
    fixture = _fixture()
    pacer = PacerLikeConfig(4, 2, 64)
    netshaper = NetShaperLikeConfig(4, 2, 64, 2, 0.01, 7)
    manifest = _manifest(fixture, pacer, netshaper)
    prepared = prepare_shared_network_baseline(manifest, fixture, "right")

    assert prepared.actions[0].ready_slot == 1
    assert prepared.network_available is fixture.network_available
    assert manifest.shared.utility_sha256 != utility_trace_digest(prepared.actions)
    pacer_result = run_pacer_like(
        prepared.runtime_manifest,
        pacer,
        prepared.actions,
        prepared.network_available,
    )
    netshaper_result = run_netshaper_like(
        prepared.runtime_manifest,
        netshaper,
        prepared.actions,
        prepared.network_available,
    )
    assert pacer_result.public_fault_slots == netshaper_result.public_fault_slots == 1
    assert pacer_result.private_deliveries[0].action_id == "notify"
    assert netshaper_result.private_deliveries[0].action_id == "notify"


def test_unknown_scenario_and_fixture_drift_fail_before_execution() -> None:
    fixture = _fixture()
    pacer = PacerLikeConfig(4, 2, 64)
    netshaper = NetShaperLikeConfig(4, 2, 64, 2, 0.01, 7)
    manifest = _manifest(fixture, pacer, netshaper)
    with pytest.raises(NetworkBaselineFixtureError) as caught:
        prepare_shared_network_baseline(manifest, fixture, "missing")
    assert caught.value.category == "unknown_scenario"

    changed = replace(fixture, network_available=(True, True, True, True))
    with pytest.raises(SharedFixtureError) as caught_shared:
        prepare_shared_network_baseline(manifest, changed, "left")
    assert caught_shared.value.category == "case_sha256_mismatch"
