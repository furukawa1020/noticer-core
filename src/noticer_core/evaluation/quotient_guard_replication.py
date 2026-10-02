"""QuotientGuard digest-linked replication and decision contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

POLICY_SCHEMA = "quotient-guard-decision-policy/v1"
MANIFEST_SCHEMA = "quotient-guard-replication-manifest/v1"
REPORT_SCHEMA = "quotient-guard-decision-report/v1"
CATEGORIES = ("GO", "PIVOT", "KILL")
COUNTS = {"GO": 9, "PIVOT": 7, "KILL": 10}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROHIBITED_FIELDS = {"raw_biosignal", "private_state", "shadow_index", "subject_id", "secret_key"}


class GuardReplicationError(ValueError):
    """Raised when a QG replication artifact violates its frozen contract."""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GuardReplicationError(f"{label} fields differ")


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise GuardReplicationError("invalid policy") from exc
    if not isinstance(policy, dict):
        raise GuardReplicationError("policy root must be an object")
    strict_keys(
        policy,
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
        policy["schema_version"] != POLICY_SCHEMA
        or policy["decision_precedence"] != ["KILL", "PIVOT", "GO"]
        or policy["missing_evidence_action"] != "PIVOT"
        or policy["hardware_status"] != "NOT_VERIFIED"
    ):
        raise GuardReplicationError("invalid frozen policy")
    criteria = policy["criteria"]
    if not isinstance(criteria, dict) or tuple(criteria) != CATEGORIES:
        raise GuardReplicationError("invalid criteria categories")
    identifiers: list[str] = []
    for category in CATEGORIES:
        group = criteria[category]
        if not isinstance(group, dict) or len(group) != COUNTS[category]:
            raise GuardReplicationError(f"invalid {category} count")
        identifiers.extend(group)
    if len(identifiers) != len(set(identifiers)):
        raise GuardReplicationError("duplicate criterion")
    paths = policy["required_package_paths"]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise GuardReplicationError("inventory must be sorted and unique")
    return policy


def build_manifest(root: Path, policy_path: Path, source_commit: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise GuardReplicationError("commit must be a full lowercase SHA")
    policy = load_policy(policy_path)
    repository = root.resolve()
    inventory = []
    for relative in policy["required_package_paths"]:
        path = (repository / relative).resolve()
        if repository not in path.parents:
            raise GuardReplicationError("inventory path escapes repository")
        try:
            encoded = path.read_bytes()
        except OSError as exc:
            raise GuardReplicationError(f"missing package file: {relative}") from exc
        inventory.append({"path": relative, "bytes": len(encoded), "sha256": digest(encoded)})
    body = {
        "schema_version": MANIFEST_SCHEMA,
        "source_commit": source_commit,
        "hardware_status": "NOT_VERIFIED",
        "generated_artifacts_committed": False,
        "policy_sha256": digest(canonical_json(policy)),
        "inventory": inventory,
    }
    return {**body, "manifest_sha256": digest(canonical_json(body))}


def verify_manifest(root: Path, policy_path: Path, manifest: dict[str, Any]) -> None:
    expected = build_manifest(root, policy_path, str(manifest.get("source_commit", "")))
    if canonical_json(manifest) != canonical_json(expected):
        raise GuardReplicationError("manifest recomputation mismatch")


def blank_evidence(policy_path: Path) -> dict[str, dict[str, object]]:
    policy = load_policy(policy_path)
    return {
        criterion: {"observed": None, "evidence_sha256": "0" * 64}
        for category in CATEGORIES
        for criterion in policy["criteria"][category]
    }


def evaluate(policy_path: Path, evidence: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    policy = load_policy(policy_path)
    if SHA256.fullmatch(manifest_sha256) is None:
        raise GuardReplicationError("invalid manifest digest")
    expected = {criterion for category in CATEGORIES for criterion in policy["criteria"][category]}
    strict_keys(evidence, expected, "evidence")
    for criterion, item in evidence.items():
        if not isinstance(item, dict):
            raise GuardReplicationError(f"invalid evidence {criterion}")
        if PROHIBITED_FIELDS.intersection(key.lower() for key in item):
            raise GuardReplicationError("prohibited private evidence")
        strict_keys(item, {"observed", "evidence_sha256"}, f"evidence {criterion}")
        if item["observed"] not in {True, False, None}:
            raise GuardReplicationError(f"invalid observation {criterion}")
        artifact_digest = item["evidence_sha256"]
        if not isinstance(artifact_digest, str) or SHA256.fullmatch(artifact_digest) is None:
            raise GuardReplicationError(f"invalid evidence digest {criterion}")
    kill = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is True]
    pivot = [key for key in policy["criteria"]["PIVOT"] if evidence[key]["observed"] is True]
    unmet_go = [key for key in policy["criteria"]["GO"] if evidence[key]["observed"] is not True]
    unknown_kill = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is None]
    decision = "KILL" if kill else "PIVOT" if pivot or unmet_go or unknown_kill else "GO"
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
        "unmet_go": unmet_go,
        "unknown_kill": unknown_kill,
        "boundaries": policy["boundaries"],
    }
    return {**body, "report_sha256": digest(canonical_json(body))}


def verify_report(report: dict[str, Any]) -> None:
    body = dict(report)
    claimed = body.pop("report_sha256", None)
    if claimed != digest(canonical_json(body)) or body.get("decision") not in CATEGORIES:
        raise GuardReplicationError("decision report digest mismatch")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(value))
    temporary.replace(path)
