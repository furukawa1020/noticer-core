from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.scalability_contract import (
    AXIS_ORDER,
    BACKENDS,
    ROOT_FIELDS,
    TARGET,
    OutcomeStatus,
    ScalabilityContractError,
    load_scalability_contract,
    scalability_contract_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "configs" / "quotient_forge" / "k7_scalability_contract_v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "k7_scalability_contract_v1.schema.json"


def _write_contract(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_contract_has_deterministic_one_factor_cases_and_target_per_backend() -> None:
    first = load_scalability_contract(CONTRACT_PATH)
    second = load_scalability_contract(CONTRACT_PATH)
    expected_profiles_per_backend = 1 + 3 * len(AXIS_ORDER) + 1
    assert len(first.cases) == expected_profiles_per_backend * len(BACKENDS) == 92
    assert len({case.case_id for case in first.cases}) == len(first.cases)
    assert first.cases == second.cases
    assert scalability_contract_sha256(first) == scalability_contract_sha256(second)
    targets = [case for case in first.cases if case.target_gate]
    assert len(targets) == len(BACKENDS)
    assert all(case.dimensions.as_dict() == TARGET for case in targets)
    assert all(case.dimensions.plant_states == 12 for case in targets)
    assert all(case.dimensions.machine_states == 8 for case in targets)
    assert all(case.dimensions.horizon == 64 for case in targets)


def test_statuses_preserve_distinct_non_completion_causes() -> None:
    assert [status.value for status in OutcomeStatus] == [
        "COMPLETED",
        "TIMEOUT",
        "MEMORY_LIMIT",
        "SOLVER_UNKNOWN",
        "PROCESS_FAILURE",
        "INVALID_CASE",
        "NOT_RUN",
    ]
    assert OutcomeStatus.TIMEOUT is not OutcomeStatus.MEMORY_LIMIT
    assert OutcomeStatus.SOLVER_UNKNOWN is not OutcomeStatus.PROCESS_FAILURE


def test_schema_and_runtime_share_root_allowlist() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["required"]) == ROOT_FIELDS
    assert set(schema["properties"]) == ROOT_FIELDS
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("section", "field", "replacement", "message"),
    [
        ("axes", "horizon", [8, 16, 32, 63], "axes differ"),
        ("target_gate", "machine_states", 7, "target_gate"),
        ("resource_limits", "wall_time_ms", 60001, "resource limits differ"),
        ("artifact_policy", "hardware_status", "VERIFIED", "artifact policy differs"),
    ],
)
def test_frozen_protocol_tampering_is_rejected(
    tmp_path: Path, section: str, field: str, replacement: object, message: str
) -> None:
    document = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    tampered = deepcopy(document)
    tampered[section][field] = replacement
    with pytest.raises(ScalabilityContractError, match=message):
        load_scalability_contract(_write_contract(tmp_path, tampered))


def test_private_fields_and_nonportable_artifact_paths_are_rejected(tmp_path: Path) -> None:
    document = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    private = deepcopy(document)
    private["subject_id"] = "forbidden"
    with pytest.raises(ScalabilityContractError, match="private field"):
        load_scalability_contract(_write_contract(tmp_path, private))

    nonportable = deepcopy(document)
    nonportable["artifact_policy"]["root"] = "artifacts\\scalability"
    with pytest.raises(ScalabilityContractError, match="artifact policy differs"):
        load_scalability_contract(_write_contract(tmp_path, nonportable))


def test_generated_artifacts_remain_uncommitted_and_hardware_unverified() -> None:
    contract = load_scalability_contract(CONTRACT_PATH)
    assert contract.artifact_root.startswith("artifacts/")
    assert contract.hardware_status == "NOT_VERIFIED"
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "artifacts/*" in gitignore

