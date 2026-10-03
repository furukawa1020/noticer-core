from dataclasses import replace

import pytest

from noticer_core.evaluation.logical_transport_cost import LogicalCostVector
from noticer_core.evaluation.transport_cost_audit import (
    CostAuditCommitment,
    CostAuditError,
    audit_cost_claim,
    calibration_digest,
)
from noticer_core.evaluation.transport_cost_profile import (
    FORMAT_VERSION as PROFILE_VERSION,
)
from noticer_core.evaluation.transport_cost_profile import (
    MeasurementInterval,
    PlatformProfile,
    build_calibration_artifact,
)
from noticer_core.evaluation.transport_cost_simulator import (
    FORMAT_VERSION,
    PublicRequest,
    TransportSimulationConfig,
    simulate_transport_cost,
)


def _artifacts():
    profile = PlatformProfile(
        PROFILE_VERSION, "sim", "public-sim", "v1", "a" * 64, "cpu-only"
    )
    config = TransportSimulationConfig(FORMAT_VERSION, "v1", 7, 8, 2, 3, 100)
    simulation = simulate_transport_cost(
        config, (PublicRequest("a", 0, 1, 8),), (True, True), profile
    )
    intervals = (
        MeasurementInterval("bytes", "bytes", 16, 16, 16),
        MeasurementInterval("radio_on_slots", "proxy_slots", 1, 1, 1),
    )
    calibration = build_calibration_artifact(
        "b" * 64, simulation.logical_cost, profile, intervals
    )
    commitment = CostAuditCommitment(
        simulation.platform_profile_sha256,
        calibration_digest(calibration),
        ("bytes", "radio_on_slots"),
    )
    return simulation, calibration, commitment


def test_honest_claim_passes_and_preserves_residual_limits() -> None:
    simulation, calibration, commitment = _artifacts()
    report = audit_cost_claim(
        simulation, calibration, simulation.logical_cost.cost, commitment
    )
    assert report.status == "PASS"
    assert report.residual_limits == (
        "measurement_source_collusion",
        "simulator_model_mismatch",
    )
    assert not report.security_proof


def _understated(cost: LogicalCostVector) -> LogicalCostVector:
    return replace(cost, bytes=cost.bytes - 1)


@pytest.mark.parametrize(
    "attack,category",
    [
        ("understate", "cost_understatement_or_substitution"),
        ("profile", "profile_substitution"),
        ("unit", "unit_confusion"),
        ("interval", "interval_or_artifact_tampering"),
        ("missing", "missing_or_reordered_measurement"),
    ],
)
def test_cost_attack_fixtures_fail_closed(attack, category) -> None:
    simulation, calibration, commitment = _artifacts()
    claimed = simulation.logical_cost.cost
    if attack == "understate":
        claimed = _understated(claimed)
    elif attack == "profile":
        calibration = replace(calibration, platform_profile_sha256="c" * 64)
    elif attack == "unit":
        intervals = (replace(calibration.intervals[0], unit="frames"),) + calibration.intervals[1:]
        calibration = replace(calibration, intervals=intervals)
    elif attack == "interval":
        intervals = (replace(calibration.intervals[0], upper=17),) + calibration.intervals[1:]
        calibration = replace(calibration, intervals=intervals)
    else:
        calibration = replace(calibration, intervals=calibration.intervals[:-1])
    with pytest.raises(CostAuditError) as caught:
        audit_cost_claim(simulation, calibration, claimed, commitment)
    assert caught.value.category == category
