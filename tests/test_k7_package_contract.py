from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.replication.k7_package import (
    K7PackageError,
    build_lock,
    load_contract,
    verify_lock,
)

CONTRACT = Path("replication/k7_package_contract_v1.json")


def _write(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_contract_has_deterministic_topological_lock() -> None:
    contract = load_contract(CONTRACT)
    lock = build_lock(contract)

    assert [task["id"] for task in contract["tasks"]] == [
        "frozen-contract",
        "semantics-certificates",
        "backend-scalability",
        "attack-composition-baseline",
        "cost-fuzz",
    ]
    assert len(lock["contract_digest"]) == 64
    assert len(lock["lock_digest"]) == 64
    assert lock["hardware_status"] == "NOT_VERIFIED"
    verify_lock(contract, lock)


def test_cycle_and_unknown_dependency_fail_closed(tmp_path: Path) -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][0]["depends_on"] = ["cost-fuzz"]
    with pytest.raises(K7PackageError, match="cycle"):
        load_contract(_write(tmp_path, value))

    value["tasks"][0]["depends_on"] = ["missing-task"]
    with pytest.raises(K7PackageError, match="invalid dependency"):
        load_contract(_write(tmp_path, value))


def test_artifact_input_requires_declared_direct_producer(tmp_path: Path) -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][2]["depends_on"] = ["frozen-contract"]

    with pytest.raises(K7PackageError, match="direct producer"):
        load_contract(_write(tmp_path, value))


def test_duplicate_output_and_host_path_fail_closed(tmp_path: Path) -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][1]["outputs"] = value["tasks"][0]["outputs"]
    with pytest.raises(K7PackageError, match="multiple producers"):
        load_contract(_write(tmp_path, value))

    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][0]["inputs"] = ["C:\\Users\\researcher\\private.json"]
    with pytest.raises(K7PackageError, match="absolute host path"):
        load_contract(_write(tmp_path, value))


def test_private_marker_and_unbounded_limit_fail_closed(tmp_path: Path) -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][0]["inputs"] = ["fixtures/raw_biosignal.json"]
    with pytest.raises(K7PackageError, match="private marker"):
        load_contract(_write(tmp_path, value))

    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    value["tasks"][0]["limits"]["timeout_seconds"] = 0
    with pytest.raises(K7PackageError, match="outside its bound"):
        load_contract(_write(tmp_path, value))


def test_tampered_lock_fails_full_recomputation() -> None:
    contract = load_contract(CONTRACT)
    lock = build_lock(contract)
    tampered = deepcopy(lock)
    tampered["tasks"][0]["task_digest"] = "0" * 64

    with pytest.raises(K7PackageError, match="full recomputation"):
        verify_lock(contract, tampered)
