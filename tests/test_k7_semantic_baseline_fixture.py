import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
)
from noticer_core.evaluation.handwritten_controls import (
    HandwrittenConfig,
    compare_matched_actions,
)
from noticer_core.evaluation.handwritten_controls import (
    config_digest as handwritten_digest,
)
from noticer_core.evaluation.observer_automata_baseline import (
    ObserverBaselineConfig,
    synthesize_hidden_signals,
)
from noticer_core.evaluation.observer_automata_baseline import (
    config_digest as automata_digest,
)
from noticer_core.evaluation.semantic_baseline_fixture import (
    SemanticBaselineFixtureError,
    prepare_shared_semantic_baselines,
)
from noticer_core.evaluation.shared_comparison_fixture import (
    FORMAT_VERSION,
    PublicAction,
    SharedComparisonFixture,
    SyntheticScenario,
    shared_contract_for_fixture,
)


def _fixture() -> SharedComparisonFixture:
    return SharedComparisonFixture(
        FORMAT_VERSION,
        "semantic-baseline-case",
        ("hint", "tick"),
        (PublicAction("notify", "service-a", 3),),
        (True, True, False, True),
        (
            SyntheticScenario(
                "left",
                False,
                (0,),
                ((False, True),) * 4,
            ),
            SyntheticScenario(
                "right",
                True,
                (2,),
                ((True, True),) * 4,
            ),
        ),
    )


def _manifest(fixture, automata, handwritten) -> ComparisonManifest:
    mechanisms = []
    for name in sorted(MECHANISMS):
        digest = (
            automata_digest(automata)
            if name == "automata"
            else handwritten_digest(handwritten)
            if name in {"handwritten_aets", "immediate_control", "leaky_control"}
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


def test_automata_and_handwritten_controls_share_one_fixture() -> None:
    fixture = _fixture()
    automata = ObserverBaselineConfig(("hint", "tick"), (1, 2), 1)
    handwritten = HandwrittenConfig(4, 64, 1)
    prepared = prepare_shared_semantic_baselines(
        _manifest(fixture, automata, handwritten),
        fixture,
        automata,
        handwritten,
    )

    assert prepared.public_actions[0].ready_slot == 0
    assert prepared.left.private_ready_slot == 0
    assert prepared.right.private_ready_slot == 2
    assert prepared.left.private_bit == 0
    assert prepared.right.private_bit == 1
    automata_result = synthesize_hidden_signals(
        prepared.automata_manifest,
        automata,
        prepared.automata_scenarios,
        prepared.public_actions,
        prepared.network_available,
    )
    handwritten_result = compare_matched_actions(
        prepared.handwritten_manifest,
        handwritten,
        prepared.left,
        prepared.right,
        prepared.network_available,
    )
    assert automata_result.status == "FINITE_OPAQUE"
    assert handwritten_result.status == "VALID"
    assert handwritten_result.aets_trace_equal


def test_signal_schema_drift_fails_closed() -> None:
    fixture = _fixture()
    automata = ObserverBaselineConfig(("hint",), (1,), 1)
    handwritten = HandwrittenConfig(4, 64, 1)
    with pytest.raises(SemanticBaselineFixtureError) as caught:
        prepare_shared_semantic_baselines(
            _manifest(fixture, automata, handwritten),
            fixture,
            automata,
            handwritten,
        )
    assert caught.value.category == "observer_signal_mismatch"
