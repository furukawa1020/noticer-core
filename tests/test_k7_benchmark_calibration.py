from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.benchmark_calibration import (
    CASE_FIELDS,
    DIFFICULTY_FIELDS,
    RESOURCE_POLICY_FIELDS,
    ROOT_FIELDS,
    STATUS_POLICY_FIELDS,
    CalibrationError,
    CalibrationScope,
    CalibrationVerdict,
    EngineObservation,
    ObservedStatus,
    ResourceReason,
    build_calibration_report,
    calibration_lock_sha256,
    evaluate_case,
    load_calibration_lock,
    write_calibration_report,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "configs" / "quotient_forge" / "benchmark_calibration_v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "k7_benchmark_calibration_v1.schema.json"


def _observation(
    case: object,
    engine_id: str,
    digest_character: str,
    *,
    status: ObservedStatus | None = None,
    reason: ResourceReason | None = None,
) -> EngineObservation:
    observed = status or ObservedStatus(case.expected_status.value)
    realizable = observed is ObservedStatus.REALIZABLE
    return EngineObservation(
        engine_id=engine_id,
        status=observed,
        evidence_sha256=digest_character * 64,
        resource_reason=reason,
        minimum_machine_states=case.difficulty.state_lower_bound if realizable else None,
        minimum_horizon=case.difficulty.horizon_lower_bound if realizable else None,
    )


def _complete_observations(lock: object) -> dict[str, tuple[EngineObservation, EngineObservation]]:
    return {
        case.family_id: (
            _observation(case, "rust-synth", "a"),
            _observation(case, "independent-oracle", "b"),
        )
        for case in lock.cases
        if case.calibration_scope is CalibrationScope.CALIBRATION
    }


def test_lock_binds_all_cases_statuses_splits_and_difficulty() -> None:
    lock = load_calibration_lock(LOCK_PATH, repository_root=ROOT)
    assert len(lock.cases) == 24
    assert len({case.case_sha256 for case in lock.cases}) == 24
    assert len({case.aqrs_sha256 for case in lock.cases}) == 24
    assert [case.family_id for case in lock.cases] == sorted(case.family_id for case in lock.cases)
    assert (
        sum(case.calibration_scope is CalibrationScope.SEALED_HELD_OUT for case in lock.cases) == 8
    )
    assert all(case.difficulty.state_lower_bound == 1 for case in lock.cases)
    assert all(case.difficulty.horizon_lower_bound == 1 for case in lock.cases)
    assert len(calibration_lock_sha256(lock)) == 64


def test_schema_and_runtime_use_the_same_exact_allowlists() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["required"]) == ROOT_FIELDS
    assert set(schema["properties"]) == ROOT_FIELDS
    assert set(schema["properties"]["status_policy"]["properties"]) == STATUS_POLICY_FIELDS
    assert set(schema["properties"]["resource_policy"]["properties"]) == RESOURCE_POLICY_FIELDS
    case_schema = schema["properties"]["cases"]["items"]
    assert set(case_schema["properties"]) == CASE_FIELDS
    assert set(case_schema["properties"]["difficulty"]["properties"]) == DIFFICULTY_FIELDS


def test_author_label_and_bound_tampering_are_rejected(tmp_path: Path) -> None:
    document = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    status_tamper = deepcopy(document)
    status_tamper["cases"][0]["expected_status"] = "INVALID_SPEC"
    status_path = tmp_path / "status.yaml"
    status_path.write_text(yaml.safe_dump(status_tamper, sort_keys=False), encoding="utf-8")
    with pytest.raises(CalibrationError, match="expected status differs"):
        load_calibration_lock(status_path, repository_root=ROOT)

    bound_tamper = deepcopy(document)
    bound_tamper["resource_policy"]["time_limit_ms"] += 1
    bound_path = tmp_path / "bound.yaml"
    bound_path.write_text(yaml.safe_dump(bound_tamper, sort_keys=False), encoding="utf-8")
    with pytest.raises(CalibrationError, match="resource_policy differs"):
        load_calibration_lock(bound_path, repository_root=ROOT)


def test_disagreement_never_overwrites_the_frozen_expected_status() -> None:
    lock = load_calibration_lock(LOCK_PATH, repository_root=ROOT)
    case = next(
        case
        for case in lock.cases
        if case.calibration_scope is CalibrationScope.CALIBRATION
        and case.expected_status.value == "REALIZABLE"
    )
    result = evaluate_case(
        case,
        _observation(case, "rust-synth", "a"),
        _observation(
            case,
            "independent-oracle",
            "b",
            status=ObservedStatus.UNSAT_AT_BOUND,
        ),
    )
    assert result.verdict is CalibrationVerdict.DISAGREEMENT
    assert result.reason == "ENGINE_DISAGREEMENT"
    assert result.expected_status is case.expected_status


@pytest.mark.parametrize(
    "reason",
    [
        ResourceReason.TIME_LIMIT,
        ResourceReason.CANDIDATE_LIMIT,
        ResourceReason.CHECKER_NODE_LIMIT,
        ResourceReason.CHECKER_DEPTH_LIMIT,
    ],
)
def test_each_resource_exhaustion_remains_inconclusive(reason: ResourceReason) -> None:
    lock = load_calibration_lock(LOCK_PATH, repository_root=ROOT)
    case = next(
        case for case in lock.cases if case.calibration_scope is CalibrationScope.CALIBRATION
    )
    result = evaluate_case(
        case,
        _observation(case, "rust-synth", "a"),
        _observation(
            case,
            "independent-oracle",
            "b",
            status=ObservedStatus.INCONCLUSIVE,
            reason=reason,
        ),
    )
    assert result.verdict is CalibrationVerdict.INCONCLUSIVE
    assert result.independent is not None
    assert result.independent.resource_reason is reason
    assert result.expected_status is case.expected_status


def test_held_out_observations_are_rejected_before_ledger_open() -> None:
    lock = load_calibration_lock(LOCK_PATH, repository_root=ROOT)
    held_out = next(
        case for case in lock.cases if case.calibration_scope is CalibrationScope.SEALED_HELD_OUT
    )
    with pytest.raises(CalibrationError, match="held-out observation is sealed"):
        evaluate_case(
            held_out,
            _observation(held_out, "rust-synth", "a"),
            _observation(held_out, "independent-oracle", "b"),
        )


def test_report_is_preopen_ready_private_free_and_idempotent(tmp_path: Path) -> None:
    lock = load_calibration_lock(LOCK_PATH, repository_root=ROOT)
    report = build_calibration_report(lock, _complete_observations(lock))
    assert report["status"] == "PREOPEN_READY"
    assert report["summary"] == {
        "agree": 16,
        "disagreement": 0,
        "inconclusive": 0,
        "sealed": 8,
    }
    assert report["private_field_count"] == 0
    output = tmp_path / "calibration.json"
    write_calibration_report(output, report)
    original = output.read_bytes()
    write_calibration_report(output, report)
    assert output.read_bytes() == original
    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="differs"):
        write_calibration_report(output, report)
