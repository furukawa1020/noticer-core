from __future__ import annotations

import json
from pathlib import Path

from noticer_core.replication.k7_audit import audit_package, load_policy
from noticer_core.replication.k7_bootstrap import ProbeResult, inspect_environment
from noticer_core.replication.k7_publication import generate_artifacts
from noticer_core.replication.k7_runner import Execution, run_package
from noticer_core.replication.manifest import canonical_json

POLICY = Path("replication/k7_audit_policy_v1.json")


def _package(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    package = tmp_path / "package"
    package.mkdir(parents=True)
    lock = {
        "schema": "noticer-core.k7-toolchain-lock.v1",
        "network_policy": "OFFLINE_INSPECTION_ONLY",
        "hardware_status": "NOT_VERIFIED",
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "toolchains": [
            {
                "argv": ["python", "--version"],
                "id": "python",
                "required_marker": "marker",
                "source": "pyproject.toml",
                "source_sha256": "a" * 64,
                "version": "3.11.x",
                "version_pattern": "^Python 3\\.11\\.[0-9]+",
            }
        ],
    }
    environment = inspect_environment(lock, lambda argv: ProbeResult(0, "Python 3.11.9"))
    (package / "environment.json").write_bytes(canonical_json(environment))
    source = package / "fixture.txt"
    source.write_text("public", encoding="utf-8")
    contract = {
        "schema": "noticer-core.k7-package-contract.v1",
        "evidence_origin": "REPOSITORY_CONTRACT",
        "hardware_status": "NOT_VERIFIED",
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "tasks": [
            {
                "category": "TEST",
                "command": ["unused"],
                "cwd": ".",
                "depends_on": [],
                "id": "public-test",
                "inputs": ["fixture.txt"],
                "limits": {"max_output_bytes": 1024, "timeout_seconds": 1},
                "outputs": ["task-result.json"],
            }
        ],
    }
    execution = Execution("PASS", "COMPLETED", 0, 0, "0" * 64)
    log = run_package(
        package,
        contract,
        environment_status="READY",
        executor=lambda task, root: execution,
    )
    (package / "run-log.json").write_bytes(canonical_json(log))
    (package / "task-result.json").unlink()
    generate_artifacts(log, package / "publication")
    source.unlink()
    return package, lock


def test_complete_public_package_passes_deterministically(tmp_path: Path) -> None:
    package, lock = _package(tmp_path)
    policy = load_policy(POLICY)

    first = audit_package(package, policy, lock)
    second = audit_package(package, policy, lock)

    assert first == second
    assert first["verdict"] == "PASS"
    assert first["release_blocker"] is False
    assert first["checked_files"] == 6


def test_unlisted_file_and_private_key_are_release_blockers(tmp_path: Path) -> None:
    package, lock = _package(tmp_path)
    (package / "extra.json").write_text(json.dumps({"subject_id": "person-1"}), encoding="utf-8")

    report = audit_package(package, load_policy(POLICY), lock)
    codes = {finding["code"] for finding in report["findings"]}

    assert report["verdict"] == "FAIL"
    assert report["release_blocker"] is True
    assert {"UNLISTED_FILE", "PROHIBITED_JSON_KEY"} <= codes


def test_credential_and_absolute_host_path_are_detected(tmp_path: Path) -> None:
    package, lock = _package(tmp_path)
    target = package / "publication/task-status.csv"
    target.write_text(
        "api_key=abcdefghijklmnop1234,C:\\Users\\researcher\\artifact.json\n",
        encoding="utf-8",
    )

    report = audit_package(package, load_policy(POLICY), lock)
    codes = {finding["code"] for finding in report["findings"]}

    assert "CREDENTIAL_PATTERN" in codes
    assert "ABSOLUTE_HOST_PATH" in codes


def test_tampered_digest_chain_is_a_release_blocker(tmp_path: Path) -> None:
    package, lock = _package(tmp_path)
    summary = json.loads((package / "publication/summary.json").read_text(encoding="utf-8"))
    summary["total_tasks"] = 99
    (package / "publication/summary.json").write_bytes(canonical_json(summary))

    report = audit_package(package, load_policy(POLICY), lock)

    assert report["verdict"] == "FAIL"
    assert report["findings"][0]["code"] == "DIGEST_CHAIN_INVALID"
