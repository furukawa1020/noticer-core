from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from noticer_core.replication.audit import (
    audit_evidence_package,
    create_evidence_index,
    render_audit_markdown,
    write_evidence_index,
)
from noticer_core.replication.manifest import canonical_json

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "replication" / "evidence_audit_policy_v1.json"
KINDS = [
    "MANIFEST",
    "REPRODUCTION_REPORT",
    "CAPSULE",
    "CERTIFICATE",
    "RELATION",
    "CONTEXT",
    "COUNTEREXAMPLE",
    "MUTATION_REPORT",
    "ENGINE_REPORT",
    "ATTACK_REPORT",
    "PERFORMANCE_REPORT",
    "ABLATION_REPORT",
    "STUDIO_EXPORT",
    "INVARIANT_REPORT",
]
OUTCOMES = {
    "ESCAPED_MUTANT": [],
    "ENGINE_DISAGREEMENT": [],
    "RESOURCE_BOUND": [],
    "UNSUPPORTED": [],
}


def _seal(value: dict[str, Any]) -> None:
    unsigned = copy.deepcopy(value)
    unsigned["artifact_sha256"] = ""
    value["artifact_sha256"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()


def _package(tmp_path: Path) -> tuple[Path, Path, list[dict[str, Any]]]:
    package = tmp_path / "package"
    package.mkdir(parents=True)
    manifest_sha = "1" * 64
    reproduction_sha = "2" * 64
    records: list[dict[str, Any]] = []
    for index, kind in enumerate(KINDS):
        path = f"evidence/{index:02d}-{kind.lower()}.json"
        destination = package / Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        artifact_sha = (
            manifest_sha
            if kind == "MANIFEST"
            else reproduction_sha
            if kind == "REPRODUCTION_REPORT"
            else hashlib.sha256(kind.encode()).hexdigest()
        )
        destination.write_bytes(
            canonical_json(
                {
                    "schema": f"fixture.{kind.lower()}.v1",
                    "verdict": "PASS",
                    "artifact_sha256": artifact_sha,
                }
            )
        )
        records.append(
            {
                "id": f"EVIDENCE_{index:02d}",
                "kind": kind,
                "path": path,
                "content_type": "JSON",
                "verdict": "PASS",
                "reason_codes": [],
            }
        )
    evidence_index = create_evidence_index(
        package, POLICY, manifest_sha, reproduction_sha, records, OUTCOMES
    )
    index_path = package / "evidence-index.json"
    write_evidence_index(evidence_index, index_path)
    return package, index_path, records


def test_complete_digest_linked_package_passes_deterministically(tmp_path: Path) -> None:
    package, index_path, _ = _package(tmp_path)
    first = audit_evidence_package(package, index_path, POLICY)
    second = audit_evidence_package(package, index_path, POLICY)

    assert first == second
    assert first["verdict"] == "PASS"
    assert first["checked_records"] == len(KINDS)
    assert first["summary"] == {"FAIL": 0, "INCONCLUSIVE": 0, "NOT_RUN": 0, "PASS": 14}
    assert first["findings"] == []
    assert render_audit_markdown(first) == render_audit_markdown(second)


def test_missing_required_kind_and_hidden_summary_are_detected(tmp_path: Path) -> None:
    package, index_path, _ = _package(tmp_path)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["records"] = index["records"][1:]
    index["summary"]["PASS"] = 14
    _seal(index)
    write_evidence_index(index, index_path)

    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert {finding["code"] for finding in report["findings"]} >= {
        "REQUIRED_EVIDENCE_MISSING",
        "VERDICT_SUMMARY_MISMATCH",
        "MANIFEST_LINK_MISMATCH",
    }


def test_tampered_artifact_and_index_unknown_field_fail_closed(tmp_path: Path) -> None:
    package, index_path, _ = _package(tmp_path)
    record = json.loads(index_path.read_text(encoding="utf-8"))["records"][3]
    (package / Path(record["path"])).write_text("tampered\n", encoding="utf-8")
    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert "ARTIFACT_DIGEST_MISMATCH" in {finding["code"] for finding in report["findings"]}

    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["unexpected"] = True
    _seal(index)
    write_evidence_index(index, index_path)
    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert [finding["code"] for finding in report["findings"]] == ["INDEX_INVALID"]


def test_prohibited_private_key_and_credential_pattern_are_detected(tmp_path: Path) -> None:
    package, index_path, records = _package(tmp_path)
    target = package / Path(records[8]["path"])
    target.write_bytes(
        canonical_json(
            {
                "schema": "fixture.engine.v1",
                "subject_id": "participant-7",
                "note": "api_key=abcdefghijklmnop1234",
            }
        )
    )
    index = create_evidence_index(package, POLICY, "1" * 64, "2" * 64, records, OUTCOMES)
    write_evidence_index(index, index_path)

    report = audit_evidence_package(package, index_path, POLICY)
    codes = {finding["code"] for finding in report["findings"]}
    assert report["verdict"] == "FAIL"
    assert "PROHIBITED_KEY_DETECTED" in codes
    assert "SECRET_PATTERN_DETECTED" in codes


def test_nonpass_ledger_requires_matching_nonpass_record(tmp_path: Path) -> None:
    package, index_path, records = _package(tmp_path)
    outcomes = {**OUTCOMES, "ENGINE_DISAGREEMENT": ["EVIDENCE_08"]}
    index = create_evidence_index(package, POLICY, "1" * 64, "2" * 64, records, outcomes)
    write_evidence_index(index, index_path)

    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert "OUTCOME_REFERENCE_INVALID" in {
        finding["code"] for finding in report["findings"]
    }


def test_explicit_nonpass_outcomes_are_preserved(tmp_path: Path) -> None:
    package, index_path, records = _package(tmp_path)
    codes = list(OUTCOMES)
    outcomes: dict[str, list[str]] = {}
    for offset, code in enumerate(codes, start=7):
        records[offset]["verdict"] = "INCONCLUSIVE"
        records[offset]["reason_codes"] = [code]
        outcomes[code] = [records[offset]["id"]]
    index = create_evidence_index(package, POLICY, "1" * 64, "2" * 64, records, outcomes)
    write_evidence_index(index, index_path)

    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "PASS"
    assert report["summary"]["INCONCLUSIVE"] == 4
    assert {outcome["code"] for outcome in report["outcomes"]} == set(OUTCOMES)


def test_path_escape_oversize_and_malformed_json_are_rejected(tmp_path: Path) -> None:
    package, index_path, records = _package(tmp_path)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["records"][0]["path"] = "../outside.json"
    _seal(index)
    write_evidence_index(index, index_path)
    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert [finding["code"] for finding in report["findings"]] == ["INDEX_INVALID"]

    package, index_path, records = _package(tmp_path / "second")
    target = package / Path(records[4]["path"])
    target.write_text("{not-json", encoding="utf-8")
    index = create_evidence_index(package, POLICY, "1" * 64, "2" * 64, records, OUTCOMES)
    write_evidence_index(index, index_path)
    report = audit_evidence_package(package, index_path, POLICY)
    assert report["verdict"] == "FAIL"
    assert "JSON_PARSE_ERROR" in {finding["code"] for finding in report["findings"]}
