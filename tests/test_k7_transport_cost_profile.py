from dataclasses import replace

import pytest

from noticer_core.evaluation.logical_transport_cost import RuntimeEvent, compute_logical_cost
from noticer_core.evaluation.transport_cost_profile import (
    FORMAT_VERSION,
    MeasurementInterval,
    PlatformProfile,
    TransportProfileError,
    build_calibration_artifact,
    canonical_calibration_json,
)


def _logical():
    return compute_logical_cost(
        (RuntimeEvent("state_count", 0, state_count=2), RuntimeEvent("frame", 0, byte_count=8))
    )


def _profile(profile_id: str = "linux-x86-smoke") -> PlatformProfile:
    return PlatformProfile(
        FORMAT_VERSION,
        profile_id,
        "public-simulator",
        "v1",
        "a" * 64,
        "ubuntu-24.04-cpu-only",
    )


def _intervals() -> tuple[MeasurementInterval, ...]:
    return (
        MeasurementInterval("bytes", "bytes", 8.0, 8.0, 8.0),
        MeasurementInterval("radio_on_slots", "proxy_slots", 0.0, 0.0, 1.0),
    )


def test_profile_change_does_not_change_security_or_logical_identity() -> None:
    first = build_calibration_artifact("b" * 64, _logical(), _profile(), _intervals())
    second = build_calibration_artifact(
        "b" * 64, _logical(), _profile("windows-x86-smoke"), _intervals()
    )
    assert first.security_contract_sha256 == second.security_contract_sha256
    assert first.logical_cost_sha256 == second.logical_cost_sha256
    assert first.platform_profile_sha256 != second.platform_profile_sha256
    assert canonical_calibration_json(first) == canonical_calibration_json(first)


@pytest.mark.parametrize(
    "profile,intervals,category",
    [
        (replace(_profile(), source_version=""), _intervals(), "missing_provenance"),
        (_profile(), (), "missing_intervals"),
        (
            _profile(),
            (MeasurementInterval("bytes", "bytes", 9.0, 8.0, 10.0),),
            "invalid_interval",
        ),
        (
            _profile(),
            (MeasurementInterval("radio_on_slots", "joule", 0.1, 0.2, 0.3),),
            "hardware_energy_overclaim",
        ),
    ],
)
def test_invalid_provenance_intervals_and_energy_claims_fail_closed(
    profile, intervals, category
) -> None:
    with pytest.raises(TransportProfileError) as caught:
        build_calibration_artifact("b" * 64, _logical(), profile, intervals)
    assert caught.value.category == category
