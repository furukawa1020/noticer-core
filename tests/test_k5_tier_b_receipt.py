from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from noticer_core.evaluation.tier_b_receipt import TierBReceiptError, build_tier_b_receipt


def _log(provenance: str = "PHYSICAL_MEASUREMENT") -> dict[str, Any]:
    duration_ns = 1_800_000_000_000
    return {
        "schema": "noticer.k5.tier_b_private_log.v1",
        "provenance": provenance,
        "preflight_digest": "a" * 64,
        "private_bundle_sha256": "b" * 64,
        "polar_sdk_version": "8.1.0",
        "firmware_version": "private-version",
        "battery_percent_start": 90.0,
        "battery_percent_end": 84.5,
        "streams": {
            "ppg": {
                "negotiated_rate_hz": 55,
                "frames": [
                    {
                        "sequence": 0,
                        "first_timestamp_ns": 0,
                        "last_timestamp_ns": duration_ns,
                        "sample_count": 99_001,
                    }
                ],
            },
            "acc": {
                "negotiated_rate_hz": 52,
                "frames": [
                    {
                        "sequence": 0,
                        "first_timestamp_ns": 0,
                        "last_timestamp_ns": duration_ns,
                        "sample_count": 93_601,
                    }
                ],
            },
        },
        "windows": [
            {"quality_pass": True, "latency_ms": 20.0, "k1_decision_emitted": True},
            {"quality_pass": False, "latency_ms": 30.0, "k1_decision_emitted": False},
        ],
        "resources": [
            {"memory_mb": 60.0, "cpu_percent": 10.0},
            {"memory_mb": 64.0, "cpu_percent": 14.0},
        ],
    }


def test_physical_log_produces_bounded_review_receipt_without_promotion() -> None:
    receipt = build_tier_b_receipt(_log())

    assert receipt["hardware_status"] == "NOT_VERIFIED"
    assert receipt["review_status"] == "READY_FOR_PHYSICAL_REVIEW"
    assert receipt["measurements"]["duration_seconds"] == 1800
    assert receipt["measurements"]["quality_pass_rate"] == 0.5
    assert receipt["measurements"]["latency_ms_p95"] == 30.0
    assert receipt["measurements"]["mean_cpu_percent"] == 12.0
    assert "firmware_version" not in receipt
    assert len(receipt["receipt_digest"]) == 64


def test_software_fixture_cannot_claim_live_input_or_physical_review() -> None:
    receipt = build_tier_b_receipt(_log("SOFTWARE_FIXTURE"))

    assert receipt["hardware_status"] == "NOT_VERIFIED"
    assert receipt["review_status"] == "SOFTWARE_FIXTURE_ONLY"
    assert receipt["measurements"]["k1_live_input_confirmed"] is False


def test_rate_drift_and_stream_rollback_fail_or_remain_visible() -> None:
    drift = _log()
    drift["streams"]["ppg"]["frames"][0]["sample_count"] = 80_000
    with pytest.raises(TierBReceiptError, match="observed rate"):
        build_tier_b_receipt(drift)

    rollback = _log()
    first = rollback["streams"]["ppg"]["frames"][0]
    first["last_timestamp_ns"] = 900_000_000_000
    first["sample_count"] = 49_501
    rollback["streams"]["ppg"]["frames"].append(
        {
            "sequence": 0,
            "first_timestamp_ns": 900_000_000_000,
            "last_timestamp_ns": 1_800_000_000_000,
            "sample_count": 49_501,
        }
    )
    receipt = build_tier_b_receipt(rollback)
    assert receipt["measurements"]["rollback_count"] == 1


def test_unknown_private_log_field_cannot_flow_to_public_receipt() -> None:
    private_log = deepcopy(_log())
    private_log["participant_id"] = "private"
    with pytest.raises(TierBReceiptError, match="root fields"):
        build_tier_b_receipt(private_log)
