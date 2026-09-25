"""Digest-linked replication manifest and Go/Pivot/Kill gate for QuotientLimit."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import yaml

POLICY_SCHEMA: Final = "quotient-limit-decision-policy/v1"
MANIFEST_SCHEMA: Final = "quotient-limit-replication-manifest/v1"
REPORT_SCHEMA: Final = "quotient-limit-decision-report/v1"
CATEGORIES: Final = ("GO", "PIVOT", "KILL")
PROHIBITED_FIELDS: Final = {
    "raw_biosignal",
    "subject_id",
    "stable_identifier",
    "secret_key",
    "baseline",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class QuotientLimitReplicationError(ValueError):
    """Raised when a K9 replication or decision artifact violates its contract."""


def canonical_json(value: object) -> bytes:
    """Encode a deterministic UTF-8 JSON artifact."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise QuotientLimitReplicationError(
            f"{label} fields differ; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def load_policy(path: Path) -> dict[str, Any]:
    """Load and strictly validate the frozen K9 decision policy."""

    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise QuotientLimitReplicationError("policy is not valid UTF-8 YAML") from exc
    if not isinstance(value, dict):
        raise QuotientLimitReplicationError("policy root must be an object")
    _strict_keys(
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
    if value["schema_version"] != POLICY_SCHEMA:
        raise QuotientLimitReplicationError("unsupported policy schema")
    if value["decision_precedence"] != ["KILL", "PIVOT", "GO"]:
        raise QuotientLimitReplicationError("decision precedence must be KILL, PIVOT, GO")
    if value["missing_evidence_action"] != "PIVOT":
        raise QuotientLimitReplicationError("missing evidence must produce PIVOT")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise QuotientLimitReplicationError("hardware status must remain NOT_VERIFIED")
    criteria = value["criteria"]
    if not isinstance(criteria, dict) or tuple(criteria) != CATEGORIES:
        raise QuotientLimitReplicationError("criteria categories must be GO, PIVOT, KILL")
    expected_counts = {"GO": 13, "PIVOT": 10, "KILL": 13}
    all_ids: list[str] = []
    for category, expected in expected_counts.items():
        group = criteria[category]
        if not isinstance(group, dict) or len(group) != expected:
            raise QuotientLimitReplicationError(f"{category} criterion count must be {expected}")
        if not all(isinstance(key, str) and isinstance(text, str) for key, text in group.items()):
            raise QuotientLimitReplicationError(
                "criterion identifiers and descriptions must be strings"
            )
        all_ids.extend(group)
    if len(all_ids) != len(set(all_ids)):
        raise QuotientLimitReplicationError("criterion identifiers must be globally unique")
    paths = value["required_package_paths"]
    if not isinstance(paths, list) or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise QuotientLimitReplicationError("required package paths must be unique and sorted")
    return value


def _resolve(root: Path, relative: str) -> Path:
    if (
        not relative
        or "\\" in relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise QuotientLimitReplicationError(f"non-canonical package path: {relative}")
    root = root.resolve()
    candidate = (root / relative).resolve()
    if root not in candidate.parents:
        raise QuotientLimitReplicationError(f"package path escapes repository: {relative}")
    return candidate


def build_manifest(root: Path, policy_path: Path, source_commit: str) -> dict[str, Any]:
    """Build a recomputable manifest over the frozen K9 package inventory."""

    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise QuotientLimitReplicationError("source commit must be a full lowercase Git SHA")
    policy = load_policy(policy_path)
    inventory: list[dict[str, object]] = []
    for relative in policy["required_package_paths"]:
        path = _resolve(root, relative)
        try:
            encoded = path.read_bytes()
        except OSError as exc:
            raise QuotientLimitReplicationError(
                f"required package file is missing: {relative}"
            ) from exc
        inventory.append({"path": relative, "bytes": len(encoded), "sha256": _digest(encoded)})
    body: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "source_commit": source_commit,
        "hardware_status": "NOT_VERIFIED",
        "generated_artifacts_committed": False,
        "policy_sha256": _digest(canonical_json(policy)),
        "inventory": inventory,
    }
    return {**body, "manifest_sha256": _digest(canonical_json(body))}


def verify_manifest(root: Path, policy_path: Path, manifest: Mapping[str, object]) -> None:
    """Recompute every manifest digest and reject mutation or path substitution."""

    _strict_keys(
        manifest,
        {
            "schema_version",
            "source_commit",
            "hardware_status",
            "generated_artifacts_committed",
            "policy_sha256",
            "inventory",
            "manifest_sha256",
        },
        "manifest",
    )
    expected = build_manifest(root, policy_path, str(manifest["source_commit"]))
    if canonical_json(manifest) != canonical_json(expected):
        raise QuotientLimitReplicationError("manifest does not match recomputed package evidence")


def _validate_evidence(policy: Mapping[str, Any], evidence: Mapping[str, object]) -> None:
    expected = {criterion for category in CATEGORIES for criterion in policy["criteria"][category]}
    _strict_keys(evidence, expected, "evidence")
    encoded = canonical_json(evidence).decode("ascii").lower()
    if any(field in encoded for field in PROHIBITED_FIELDS):
        raise QuotientLimitReplicationError("evidence contains a prohibited private-data field")
    for criterion, raw in evidence.items():
        if not isinstance(raw, dict):
            raise QuotientLimitReplicationError(f"evidence.{criterion} must be an object")
        _strict_keys(raw, {"observed", "evidence_sha256"}, f"evidence.{criterion}")
        if raw["observed"] not in {True, False, None}:
            raise QuotientLimitReplicationError(f"evidence.{criterion}.observed is invalid")
        digest = raw["evidence_sha256"]
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise QuotientLimitReplicationError(f"evidence.{criterion}.evidence_sha256 is invalid")


def evaluate_decision(
    policy_path: Path,
    evidence: Mapping[str, object],
    manifest_sha256: str,
) -> dict[str, Any]:
    """Evaluate the frozen non-compensatory K9 decision gate."""

    policy = load_policy(policy_path)
    if _SHA256.fullmatch(manifest_sha256) is None:
        raise QuotientLimitReplicationError("manifest_sha256 is invalid")
    _validate_evidence(policy, evidence)
    kill = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is True]
    pivot = [key for key in policy["criteria"]["PIVOT"] if evidence[key]["observed"] is True]
    unmet_go = [key for key in policy["criteria"]["GO"] if evidence[key]["observed"] is not True]
    unknown_kill = [key for key in policy["criteria"]["KILL"] if evidence[key]["observed"] is None]
    if kill:
        decision = "KILL"
    elif pivot or unmet_go or unknown_kill:
        decision = "PIVOT"
    else:
        decision = "GO"
    evidence_sha256 = _digest(canonical_json(evidence))
    body: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "decision": decision,
        "aggregation": "NON_COMPENSATORY",
        "hardware_status": "NOT_VERIFIED",
        "manifest_sha256": manifest_sha256,
        "policy_sha256": _digest(canonical_json(policy)),
        "evidence_sha256": evidence_sha256,
        "triggered_kill": kill,
        "triggered_pivot": pivot,
        "unmet_go": unmet_go,
        "unknown_kill": unknown_kill,
        "boundaries": policy["boundaries"],
    }
    return {**body, "report_sha256": _digest(canonical_json(body))}


def verify_decision_report(report: Mapping[str, object]) -> None:
    """Reject a mutated decision report."""

    body = dict(report)
    digest = body.pop("report_sha256", None)
    if not isinstance(digest, str) or digest != _digest(canonical_json(body)):
        raise QuotientLimitReplicationError("decision report SHA-256 mismatch")
    if body.get("decision") not in CATEGORIES:
        raise QuotientLimitReplicationError("decision report has an invalid decision")


def write_json(path: Path, value: object) -> None:
    """Atomically write a generated artifact outside the tracked source inventory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(value))
    temporary.replace(path)


def blank_evidence(policy_path: Path) -> dict[str, dict[str, object]]:
    """Return explicit unknown observations for a new replication run."""

    policy = load_policy(policy_path)
    return {
        criterion: {"observed": None, "evidence_sha256": "0" * 64}
        for category in CATEGORIES
        for criterion in policy["criteria"][category]
    }
