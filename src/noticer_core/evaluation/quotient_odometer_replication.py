"""Digest-linked K10 replication package and non-compensatory decision gate."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

POLICY_SCHEMA = "quotient-odometer-decision-policy/v1"
MANIFEST_SCHEMA = "quotient-odometer-replication-manifest/v1"
REPORT_SCHEMA = "quotient-odometer-decision-report/v1"
CATEGORIES = ("GO", "PIVOT", "KILL")
COUNTS = {"GO": 10, "PIVOT": 8, "KILL": 10}
SHA = re.compile(r"^[0-9a-f]{64}$")
PROHIBITED = ("raw_biosignal", "subject_id", "stable_identifier", "secret_key", "baseline")


class OdometerReplicationError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise OdometerReplicationError(f"{label} fields differ")


def load_policy(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise OdometerReplicationError("invalid policy") from exc
    if not isinstance(value, dict):
        raise OdometerReplicationError("policy root must be object")
    strict(
        value,
        {
            "schema_version",
            "decision_precedence",
            "missing_evidence_action",
            "hardware_status",
            "boundaries",
            "required_package_paths",
            "criteria",
        },
        "policy",
    )
    if (
        value["schema_version"] != POLICY_SCHEMA
        or value["decision_precedence"] != ["KILL", "PIVOT", "GO"]
        or value["missing_evidence_action"] != "PIVOT"
        or value["hardware_status"] != "NOT_VERIFIED"
    ):
        raise OdometerReplicationError("invalid frozen policy")
    if not isinstance(value["criteria"], dict) or tuple(value["criteria"]) != CATEGORIES:
        raise OdometerReplicationError("invalid categories")
    ids = []
    for category in CATEGORIES:
        group = value["criteria"][category]
        if not isinstance(group, dict) or len(group) != COUNTS[category]:
            raise OdometerReplicationError(f"invalid {category} count")
        ids.extend(group)
    if len(ids) != len(set(ids)):
        raise OdometerReplicationError("duplicate criterion")
    paths = value["required_package_paths"]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise OdometerReplicationError("inventory must be sorted and unique")
    return value


def build_manifest(root: Path, policy_path: Path, commit: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise OdometerReplicationError("commit must be full lowercase SHA")
    policy = load_policy(policy_path)
    inventory = []
    resolved = root.resolve()
    for relative in policy["required_package_paths"]:
        path = (resolved / relative).resolve()
        if resolved not in path.parents:
            raise OdometerReplicationError("path escapes repository")
        try:
            encoded = path.read_bytes()
        except OSError as exc:
            raise OdometerReplicationError(f"missing package file: {relative}") from exc
        inventory.append({"path": relative, "bytes": len(encoded), "sha256": digest(encoded)})
    body = {
        "schema_version": MANIFEST_SCHEMA,
        "source_commit": commit,
        "hardware_status": "NOT_VERIFIED",
        "generated_artifacts_committed": False,
        "policy_sha256": digest(canonical_json(policy)),
        "inventory": inventory,
    }
    return {**body, "manifest_sha256": digest(canonical_json(body))}


def verify_manifest(root: Path, policy_path: Path, manifest: dict[str, Any]) -> None:
    expected = build_manifest(root, policy_path, str(manifest.get("source_commit", "")))
    if canonical_json(manifest) != canonical_json(expected):
        raise OdometerReplicationError("manifest recomputation mismatch")


def blank_evidence(policy_path: Path) -> dict[str, dict[str, object]]:
    policy = load_policy(policy_path)
    return {
        key: {"observed": None, "evidence_sha256": "0" * 64}
        for category in CATEGORIES
        for key in policy["criteria"][category]
    }


def evaluate(policy_path: Path, evidence: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    policy = load_policy(policy_path)
    if SHA.fullmatch(manifest_sha256) is None:
        raise OdometerReplicationError("invalid manifest digest")
    expected = {key for category in CATEGORIES for key in policy["criteria"][category]}
    strict(evidence, expected, "evidence")
    if any(term in canonical_json(evidence).decode().lower() for term in PROHIBITED):
        raise OdometerReplicationError("prohibited private evidence")
    for key, item in evidence.items():
        if not isinstance(item, dict):
            raise OdometerReplicationError(f"invalid evidence {key}")
        strict(item, {"observed", "evidence_sha256"}, f"evidence {key}")
        if (
            item["observed"] not in (True, False, None)
            or not isinstance(item["evidence_sha256"], str)
            or SHA.fullmatch(item["evidence_sha256"]) is None
        ):
            raise OdometerReplicationError(f"invalid evidence {key}")
    kill = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is True]
    pivot = [key for key in policy["criteria"]["PIVOT"] if evidence[key]["observed"] is True]
    unmet = [key for key in policy["criteria"]["GO"] if evidence[key]["observed"] is not True]
    unknown = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is None]
    decision = "KILL" if kill else "PIVOT" if pivot or unmet or unknown else "GO"
    body = {
        "schema_version": REPORT_SCHEMA,
        "decision": decision,
        "aggregation": "NON_COMPENSATORY",
        "hardware_status": "NOT_VERIFIED",
        "manifest_sha256": manifest_sha256,
        "policy_sha256": digest(canonical_json(policy)),
        "evidence_sha256": digest(canonical_json(evidence)),
        "triggered_kill": kill,
        "triggered_pivot": pivot,
        "unmet_go": unmet,
        "unknown_kill": unknown,
        "boundaries": policy["boundaries"],
    }
    return {**body, "report_sha256": digest(canonical_json(body))}


def verify_report(report: dict[str, Any]) -> None:
    body = dict(report)
    claimed = body.pop("report_sha256", None)
    if claimed != digest(canonical_json(body)) or body.get("decision") not in CATEGORIES:
        raise OdometerReplicationError("decision report digest mismatch")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(value))
    temporary.replace(path)
