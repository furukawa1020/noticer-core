from __future__ import annotations

import copy
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from noticer_core.replication.archive import (
    ArchiveError,
    assemble_archive_staging,
    build_final_report,
    build_replication_archive,
    load_archive_policy,
    verify_final_report,
    verify_replication_archive,
    write_final_report,
)
from noticer_core.replication.decision import AXES, evaluate_decision
from noticer_core.replication.manifest import canonical_json

POLICY = Path("replication/archive_policy_v1.json")
DECISION_POLICY = Path("replication/decision_policy_v1.json")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value) + b"\n")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decision_input(links: dict[str, str]) -> dict[str, object]:
    metrics: dict[str, dict[str, int | float]] = {axis: {} for axis in AXES}
    metrics["security"] = {"invalid_cases": 0}
    metrics["utility"] = {"retention_ratio": 0.98}
    metrics["mutation"] = {"critical_escaped_mutants": 0}
    metrics["engine"] = {"disagreements": 0}
    metrics["attack"] = {"identity_advantage": 0.01}
    metrics["performance"] = {"overhead_ratio": 1.2}
    axes = {
        axis: {
            "status": "PASS",
            "artifact_sha256": f"{index + 100:064x}",
            "reason_codes": [],
            "metrics": metrics[axis],
        }
        for index, axis in enumerate(AXES)
    }
    axes["manifest"]["artifact_sha256"] = links["manifest_sha256"]
    axes["reproduction"]["artifact_sha256"] = links["reproduction_sha256"]
    axes["evidence_audit"]["artifact_sha256"] = links[
        "evidence_audit_sha256"
    ]
    return {
        "schema_version": "quotient-seal-decision-input/v1",
        "run_id": "archive-fixture-v1",
        "scope": "QUOTIENTSEAL_SOFTWARE_EVALUATION",
        "source_commit": "b" * 40,
        "hardware_status": "NOT_VERIFIED",
        "artifacts": links,
        "axes": axes,
    }


def _staging(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "README.md").write_text(
        "# QuotientSeal replication fixture\n\nSoftware evidence only.\n",
        encoding="utf-8",
        newline="\n",
    )
    _write_json(root / "contracts/archive-policy.json", load_archive_policy(POLICY))
    (root / "contracts/decision-policy.json").parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    (root / "contracts/decision-policy.json").write_bytes(
        DECISION_POLICY.read_bytes()
    )
    (root / "contracts/evidence-audit-policy.json").write_bytes(
        Path("replication/evidence_audit_policy_v1.json").read_bytes()
    )
    (root / "contracts/reproduction-plan.json").write_bytes(
        Path("replication/reproduction_plan_v1.json").read_bytes()
    )
    _write_json(
        root / "evidence/replication-manifest.json",
        {"schema_version": "fixture-manifest/v1", "verdict": "PASS"},
    )
    _write_json(
        root / "evidence/reproduction-report.json",
        {"schema_version": "fixture-reproduction/v1", "verdict": "PASS"},
    )
    _write_json(
        root / "evidence/evidence-audit.json",
        {"schema_version": "fixture-audit/v1", "verdict": "PASS"},
    )
    _write_json(
        root / "evidence/evidence-index.json",
        {"schema_version": "fixture-index/v1", "explicit_outcomes": []},
    )
    links = {
        "manifest_sha256": _digest(root / "evidence/replication-manifest.json"),
        "reproduction_sha256": _digest(root / "evidence/reproduction-report.json"),
        "evidence_audit_sha256": _digest(root / "evidence/evidence-audit.json"),
    }
    decision_input = _decision_input(links)
    _write_json(root / "evidence/decision-input.json", decision_input)
    _write_json(
        root / "evidence/decision.json",
        evaluate_decision(decision_input, DECISION_POLICY),
    )
    _write_json(
        root / "evidence/exact-commands.json",
        {
            "schema_version": "quotient-seal-exact-commands/v1",
            "network_policy": "OFFLINE",
            "commands": [
                {
                    "step_id": "PYTHON_TEST",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "expected_exit_code": 0,
                }
            ],
        },
    )
    _write_json(
        root / "evidence/nonpass-outcomes.json",
        {
            "schema_version": "quotient-seal-nonpass-outcomes/v1",
            "declared_count": 0,
            "outcomes": [],
        },
    )
    _write_json(
        root / "evidence/studio-export-summary.json",
        {
            "schema_version": "quotient-seal-studio-export-summary/v1",
            "export_sha256": "c" * 64,
            "size_bytes": 4096,
            "private_fields_included": False,
            "hardware_status": "NOT_VERIFIED",
        },
    )
    return root


def test_archive_is_byte_identical_and_verifies(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "staging")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_index = build_replication_archive(staging, first, POLICY)
    second_index = build_replication_archive(staging, second, POLICY)
    assert first.read_bytes() == second.read_bytes()
    assert first_index == second_index == verify_replication_archive(first, POLICY)
    assert first_index["decision"]["value"] == "GO"
    assert first_index["hardware_status"] == "NOT_VERIFIED"


def test_archive_metadata_and_order_are_fixed(tmp_path: Path) -> None:
    archive_path = tmp_path / "fixed.zip"
    build_replication_archive(_staging(tmp_path / "staging"), archive_path, POLICY)
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == sorted(
            info.filename for info in infos
        )
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        assert all(info.external_attr >> 16 == 0o100644 for info in infos)


def test_final_report_is_deterministic_and_tamper_evident(tmp_path: Path) -> None:
    archive_path = tmp_path / "bundle.zip"
    build_replication_archive(_staging(tmp_path / "staging"), archive_path, POLICY)
    first = build_final_report(archive_path, POLICY)
    second = build_final_report(archive_path, POLICY)
    assert first == second
    assert first["verification"]["verdict"] == "PASS"
    verify_final_report(first, archive_path, POLICY)
    report_path = tmp_path / "final-report.json"
    write_final_report(first, report_path, archive_path, POLICY)
    assert json.loads(report_path.read_text(encoding="utf-8")) == first
    tampered = copy.deepcopy(first)
    tampered["decision"]["value"] = "KILL"
    with pytest.raises(ArchiveError, match="does not match"):
        verify_final_report(tampered, archive_path, POLICY)


def test_staging_allowlist_rejects_unknown_and_missing_files(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "unknown")
    (staging / "unexpected.txt").write_text("no", encoding="utf-8")
    with pytest.raises(ArchiveError, match="allowlist mismatch"):
        build_replication_archive(staging, tmp_path / "unknown.zip", POLICY)

    staging = _staging(tmp_path / "missing")
    (staging / "README.md").unlink()
    with pytest.raises(ArchiveError, match="allowlist mismatch"):
        build_replication_archive(staging, tmp_path / "missing.zip", POLICY)


def test_decision_chain_and_artifact_cross_links_fail_closed(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "decision")
    report_path = staging / "evidence/decision.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["decision"] = "KILL"
    _write_json(report_path, report)
    with pytest.raises(ArchiveError, match="decision chain is invalid"):
        build_replication_archive(staging, tmp_path / "decision.zip", POLICY)

    staging = _staging(tmp_path / "link")
    manifest_path = staging / "evidence/replication-manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(ArchiveError, match="manifest_sha256"):
        build_replication_archive(staging, tmp_path / "link.zip", POLICY)


def test_secret_private_field_and_nonpass_hiding_are_rejected(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "private")
    summary_path = staging / "evidence/studio-export-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["raw_signal"] = [1, 2, 3]
    _write_json(summary_path, summary)
    with pytest.raises(ArchiveError, match="prohibited key"):
        build_replication_archive(staging, tmp_path / "private.zip", POLICY)

    staging = _staging(tmp_path / "outcomes")
    outcomes_path = staging / "evidence/nonpass-outcomes.json"
    outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))
    outcomes["declared_count"] = 1
    _write_json(outcomes_path, outcomes)
    with pytest.raises(ArchiveError, match="count does not match"):
        build_replication_archive(staging, tmp_path / "outcomes.zip", POLICY)


def test_commands_must_be_offline_argv_not_shell_text(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "commands")
    commands_path = staging / "evidence/exact-commands.json"
    commands = json.loads(commands_path.read_text(encoding="utf-8"))
    commands["network_policy"] = "ONLINE"
    _write_json(commands_path, commands)
    with pytest.raises(ArchiveError, match="OFFLINE"):
        build_replication_archive(staging, tmp_path / "commands.zip", POLICY)


def test_assembler_copies_only_exact_validated_sources(tmp_path: Path) -> None:
    source = _staging(tmp_path / "source")
    policy = load_archive_policy(POLICY)
    sources = {
        entry["path"]: source.joinpath(*entry["path"].split("/"))
        for entry in policy["required_entries"]
    }
    destination = tmp_path / "assembled"
    assemble_archive_staging(sources, destination, POLICY)
    archive_path = tmp_path / "assembled.zip"
    build_replication_archive(destination, archive_path, POLICY)
    verify_replication_archive(archive_path, POLICY)

    incomplete = dict(sources)
    incomplete.pop("README.md")
    with pytest.raises(ArchiveError, match="exactly equal"):
        assemble_archive_staging(incomplete, tmp_path / "bad", POLICY)


def test_existing_output_and_corrupt_zip_are_rejected(tmp_path: Path) -> None:
    staging = _staging(tmp_path / "staging")
    output = tmp_path / "existing.zip"
    output.write_bytes(b"existing")
    with pytest.raises(ArchiveError, match="already exists"):
        build_replication_archive(staging, output, POLICY)
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"not a zip")
    with pytest.raises(ArchiveError, match="cannot verify"):
        verify_replication_archive(corrupt, POLICY)
