from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
)
from noticer_core.evaluation.baseline_parameter_sweep import (
    AxisMetrics,
    CandidateObservation,
    build_sweep_report,
)
from noticer_core.evaluation.handwritten_controls import (
    HandwrittenConfig,
)
from noticer_core.evaluation.handwritten_controls import (
    config_digest as handwritten_digest,
)
from noticer_core.evaluation.netshaper_like import (
    NetShaperLikeConfig,
    run_netshaper_like,
)
from noticer_core.evaluation.netshaper_like import (
    config_digest as netshaper_digest,
)
from noticer_core.evaluation.network_baseline_fixture import prepare_shared_network_baseline
from noticer_core.evaluation.observer_automata_baseline import (
    ObserverBaselineConfig,
)
from noticer_core.evaluation.observer_automata_baseline import (
    config_digest as automata_digest,
)
from noticer_core.evaluation.pacer_like import (
    PacerLikeConfig,
    run_pacer_like,
)
from noticer_core.evaluation.pacer_like import (
    config_digest as pacer_digest,
)
from noticer_core.evaluation.semantic_baseline_fixture import prepare_shared_semantic_baselines
from noticer_core.evaluation.shared_comparison_fixture import (
    FORMAT_VERSION,
    PublicAction,
    SharedComparisonFixture,
    SharedFixtureError,
    SyntheticScenario,
    shared_contract_for_fixture,
)


def _inputs():
    fixture = SharedComparisonFixture(
        FORMAT_VERSION, "single-manifest", ("hint", "tick"),
        (PublicAction("notify", "service-a", 3),), (True, True, False, True),
        (
            SyntheticScenario("left", False, (0,), ((False, True),) * 4),
            SyntheticScenario("right", True, (2,), ((True, True),) * 4),
        ),
    )
    pacer = PacerLikeConfig(4, 2, 64)
    netshaper = NetShaperLikeConfig(4, 2, 64, 2, 0.01, 7)
    automata = ObserverBaselineConfig(("hint", "tick"), (1, 2), 1)
    handwritten = HandwrittenConfig(4, 64, 1)
    digests = {
        "pacer_like": pacer_digest(pacer),
        "netshaper_like": netshaper_digest(netshaper),
        "automata": automata_digest(automata),
        "handwritten_aets": handwritten_digest(handwritten),
        "immediate_control": handwritten_digest(handwritten),
        "leaky_control": handwritten_digest(handwritten),
        "aqrs": "a" * 64,
    }
    mechanisms = tuple(
        Mechanism(
            name,
            "approximation" if name in {"automata", "netshaper_like", "pacer_like"} else "local",
            "notion-" + name, "source-" + name, "v1",
            (digests[name],), digests[name],
        )
        for name in sorted(MECHANISMS)
    )
    manifest = ComparisonManifest(
        "noticer.k7.baseline-comparison.v1", shared_contract_for_fixture(fixture),
        mechanisms, AXES, True,
    )
    return fixture, manifest, pacer, netshaper, automata, handwritten


def test_one_manifest_drives_all_baseline_sections() -> None:
    fixture, manifest, pacer, netshaper, automata, handwritten = _inputs()
    network = prepare_shared_network_baseline(manifest, fixture, "right")
    run_pacer_like(network.runtime_manifest, pacer, network.actions, network.network_available)
    run_netshaper_like(
        network.runtime_manifest, netshaper, network.actions, network.network_available
    )
    semantic = prepare_shared_semantic_baselines(
        manifest, fixture, automata, handwritten
    )
    observations = tuple(
        CandidateObservation(
            mechanism.mechanism_id, mechanism.selected_config_sha256, split,
            mechanism.privacy_notion, AxisMetrics(0.0, 0, 0, 0.0, 0),
        )
        for mechanism in manifest.mechanisms
        for split in ("development", "held_out")
    )
    report = build_sweep_report(manifest, observations)
    assert len(report.selected_candidates) == len(MECHANISMS) == 7
    assert len(report.privacy_notion_sections) == 7
    assert semantic.left.action_id == network.actions[0].action_id == "notify"


def test_shared_manifest_tampering_is_rejected_across_adapters() -> None:
    fixture, manifest, pacer, netshaper, automata, handwritten = _inputs()
    tampered = replace(
        manifest, shared=replace(manifest.shared, observer_sha256="f" * 64)
    )
    with pytest.raises(SharedFixtureError):
        prepare_shared_network_baseline(tampered, fixture, "left")
    with pytest.raises(SharedFixtureError):
        prepare_shared_semantic_baselines(tampered, fixture, automata, handwritten)
