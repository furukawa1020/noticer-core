from __future__ import annotations

from copy import deepcopy

import pytest

from noticer_core.replication.k7_cross_environment import (
    K7CrossEnvironmentError,
    compare_observations,
    validate_observation,
)


def _observation(platform: str) -> dict[str, object]:
    return {
        "schema": "noticer-core.k7-platform-observation.v1",
        "platform": platform,
        "contract_digest": "a" * 64,
        "semantic_artifacts": {
            "publication/summary.json": "b" * 64,
            "run-log.json": "c" * 64,
        },
        "measurements": {
            "python_version": "3.11.9",
            "wall_time_bucket": "under-10s",
        },
        "audit_verdict": "PASS",
    }


def test_matching_semantics_verify_independent_replication() -> None:
    windows = _observation("windows")
    linux = _observation("linux")
    linux["measurements"]["wall_time_bucket"] = "10s-to-30s"

    report = compare_observations([windows, linux])

    assert report["semantic_status"] == "MATCH"
    assert report["independent_replication"] == "VERIFIED"
    assert report["semantic_differences"] == []
    assert report["measurement_differences"] == [
        {"key": "wall_time_bucket", "linux": "10s-to-30s", "windows": "under-10s"}
    ]


def test_semantic_difference_cannot_be_hidden_by_measurements() -> None:
    windows = _observation("windows")
    linux = _observation("linux")
    linux["semantic_artifacts"]["run-log.json"] = "d" * 64

    report = compare_observations([windows, linux])

    assert report["semantic_status"] == "DISAGREEMENT"
    assert report["independent_replication"] == "NOT_VERIFIED"
    assert report["semantic_differences"][0]["path"] == "run-log.json"


def test_failed_audit_keeps_replication_not_verified() -> None:
    windows = _observation("windows")
    linux = _observation("linux")
    linux["audit_verdict"] = "FAIL"

    report = compare_observations([windows, linux])

    assert report["semantic_status"] == "MATCH"
    assert report["independent_replication"] == "NOT_VERIFIED"


def test_missing_platform_duplicate_and_host_path_fail_closed() -> None:
    windows = _observation("windows")
    with pytest.raises(K7CrossEnvironmentError, match="one Windows"):
        compare_observations([windows, deepcopy(windows)])

    invalid = _observation("linux")
    invalid["measurements"]["workspace"] = "C:\\Users\\researcher\\repo"
    with pytest.raises(K7CrossEnvironmentError, match="absolute host path"):
        validate_observation(invalid)
