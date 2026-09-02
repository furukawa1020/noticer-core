"""Bounded completeness and secret non-inclusion audit for evidence packages."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from noticer_core.replication.manifest import canonical_json

POLICY_SCHEMA = "quotient-seal.evidence-audit-policy.v1"
INDEX_SCHEMA = "quotient-seal.evidence-index.v1"
AUDIT_SCHEMA = "quotient-seal.evidence-audit-report.v1"
AuditVerdict = Literal["PASS", "FAIL", "INCONCLUSIVE"]

_POLICY_KEYS = {
    "schema",
    "required_kinds",
    "required_outcome_codes",
    "allowed_content_types",
    "limits",
    "prohibited_keys",
    "prohibited_path_suffixes",
    "secret_pattern_ids",
    "audit_scope",
    "evidence_origin",
    "security_interpretation",
    "hardware_status",
}
_LIMIT_KEYS = {
    "max_index_bytes",
    "max_records",
    "max_artifact_bytes",
    "max_total_bytes",
    "max_json_depth",
    "max_json_nodes",
}
_INDEX_KEYS = {
    "schema",
    "manifest_sha256",
    "reproduction_report_sha256",
    "records",
    "summary",
    "outcomes",
    "evidence_origin",
    "hardware_status",
    "artifact_sha256",
}
_RECORD_SPEC_KEYS = {"id", "kind", "path", "content_type", "verdict", "reason_codes"}
_RECORD_KEYS = _RECORD_SPEC_KEYS | {"bytes", "sha256"}
_OUTCOME_KEYS = {"code", "count", "artifact_ids"}
_SUMMARY_KEYS = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "PEM_PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
    ),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{32,}\b"),
    "BEARER_TOKEN": re.compile(
        r"\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}",
        re.IGNORECASE,
    ),
    "GENERIC_SECRET_ASSIGNMENT": re.compile(
        r"\b(?:password|api[_-]?key|secret)\s*[:=]\s*[\"']?[A-Za-z0-9/+_.=-]{16,}",
        re.IGNORECASE,
    ),
}


class AuditError(ValueError):
    """Raised when an audit contract cannot be parsed safely."""


def _exact_keys(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown or missing:
        raise AuditError(
            f"{location} fields mismatch: unknown={sorted(unknown)}, missing={sorted(missing)}"
        )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sealed_digest(value: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(value)
    unsigned["artifact_sha256"] = ""
    return _sha256(canonical_json(unsigned))


def _load_json(path: Path, maximum: int, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > maximum:
        raise AuditError(f"{label} is missing or exceeds its byte bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be a JSON object")
    return value


def load_audit_policy(policy_path: Path) -> dict[str, Any]:
    """Load the frozen bounded audit taxonomy."""

    value = _load_json(policy_path, 1024 * 1024, "audit policy")
    _exact_keys(value, _POLICY_KEYS, "policy")
    if value["schema"] != POLICY_SCHEMA:
        raise AuditError("audit policy schema is unsupported")
    limits = value["limits"]
    if not isinstance(limits, dict):
        raise AuditError("audit limits must be an object")
    _exact_keys(limits, _LIMIT_KEYS, "policy.limits")
    if not all(isinstance(limit, int) and limit > 0 for limit in limits.values()):
        raise AuditError("audit limits must be positive integers")
    for field in (
        "required_kinds",
        "required_outcome_codes",
        "allowed_content_types",
        "prohibited_keys",
        "prohibited_path_suffixes",
        "secret_pattern_ids",
    ):
        entries = value[field]
        if (
            not isinstance(entries, list)
            or not entries
            or not all(isinstance(entry, str) and entry for entry in entries)
            or len(entries) != len(set(entries))
        ):
            raise AuditError(f"policy.{field} must be a unique non-empty string list")
    if set(value["secret_pattern_ids"]) != set(_SECRET_PATTERNS):
        raise AuditError("audit secret pattern taxonomy is incomplete or unknown")
    if value["audit_scope"] != "BOUNDED_PATTERN_AND_STRUCTURAL_AUDIT":
        raise AuditError("audit scope is unsupported")
    if value["evidence_origin"] != "SOFTWARE_AUDIT":
        raise AuditError("audit evidence origin is unsupported")
    if value["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise AuditError("audit must not claim a security verdict")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise AuditError("audit hardware status must remain NOT_VERIFIED")
    return value


def _canonical_package_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AuditError("evidence path must be a non-empty POSIX path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise AuditError(f"evidence path is not canonical: {value}")
    return value


def _resolve_package_file(root: Path, relative: str) -> Path:
    relative = _canonical_package_path(relative)
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*PurePosixPath(relative).parts)
    if candidate.is_symlink():
        raise AuditError(f"evidence symlink is not allowed: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise AuditError(f"evidence file is missing: {relative}") from error
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise AuditError(f"evidence path escapes package: {relative}")
    if not resolved.is_file():
        raise AuditError(f"evidence path is not a file: {relative}")
    return resolved


def _validate_record_spec(record: dict[str, Any], policy: dict[str, Any], location: str) -> None:
    _exact_keys(record, _RECORD_SPEC_KEYS, location)
    if not isinstance(record["id"], str) or not _IDENTIFIER.fullmatch(record["id"]):
        raise AuditError(f"{location}.id is invalid")
    if record["kind"] not in policy["required_kinds"]:
        raise AuditError(f"{location}.kind is unknown")
    _canonical_package_path(record["path"])
    if record["content_type"] not in policy["allowed_content_types"]:
        raise AuditError(f"{location}.content_type is unknown")
    if record["verdict"] not in _SUMMARY_KEYS:
        raise AuditError(f"{location}.verdict is unknown")
    reason_codes = record["reason_codes"]
    if (
        not isinstance(reason_codes, list)
        or not all(isinstance(code, str) and _IDENTIFIER.fullmatch(code) for code in reason_codes)
        or len(reason_codes) != len(set(reason_codes))
    ):
        raise AuditError(f"{location}.reason_codes is invalid")


def create_evidence_index(
    package_root: Path,
    policy_path: Path,
    manifest_sha256: str,
    reproduction_report_sha256: str,
    record_specs: list[dict[str, Any]],
    outcome_counts: dict[str, list[str]],
) -> dict[str, Any]:
    """Create a digest-linked index from a fixed list of package-relative files."""

    policy = load_audit_policy(policy_path)
    if not _SHA256.fullmatch(manifest_sha256) or not _SHA256.fullmatch(
        reproduction_report_sha256
    ):
        raise AuditError("upstream artifact digest is malformed")
    if not record_specs or len(record_specs) > policy["limits"]["max_records"]:
        raise AuditError("evidence record count is outside its bound")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    paths: set[str] = set()
    total_bytes = 0
    for index, spec in enumerate(record_specs):
        _validate_record_spec(spec, policy, f"records[{index}]")
        if spec["id"] in identifiers or spec["path"] in paths:
            raise AuditError("evidence record id or path is duplicated")
        identifiers.add(spec["id"])
        paths.add(spec["path"])
        path = _resolve_package_file(package_root, spec["path"])
        encoded = path.read_bytes()
        if len(encoded) > policy["limits"]["max_artifact_bytes"]:
            raise AuditError(f"evidence artifact exceeds byte bound: {spec['id']}")
        total_bytes += len(encoded)
        if total_bytes > policy["limits"]["max_total_bytes"]:
            raise AuditError("evidence package exceeds total byte bound")
        records.append({**spec, "bytes": len(encoded), "sha256": _sha256(encoded)})

    expected_codes = set(policy["required_outcome_codes"])
    if set(outcome_counts) != expected_codes:
        raise AuditError("non-pass outcome ledger is incomplete or unknown")
    outcomes = [
        {
            "code": code,
            "count": len(outcome_counts[code]),
            "artifact_ids": sorted(outcome_counts[code]),
        }
        for code in sorted(expected_codes)
    ]
    verdicts = [record["verdict"] for record in records]
    value: dict[str, Any] = {
        "schema": INDEX_SCHEMA,
        "manifest_sha256": manifest_sha256,
        "reproduction_report_sha256": reproduction_report_sha256,
        "records": sorted(records, key=lambda record: record["id"]),
        "summary": {verdict: verdicts.count(verdict) for verdict in sorted(_SUMMARY_KEYS)},
        "outcomes": outcomes,
        "evidence_origin": "SOFTWARE_EVIDENCE_PACKAGE",
        "hardware_status": "NOT_VERIFIED",
        "artifact_sha256": "",
    }
    value["artifact_sha256"] = _sealed_digest(value)
    return value


def write_evidence_index(index: dict[str, Any], output_path: Path) -> None:
    """Atomically write one canonical evidence index."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(f"{output_path.suffix}.tmp")
    temporary.write_bytes(canonical_json(index))
    temporary.replace(output_path)


def _finding(
    code: str,
    message: str,
    *,
    record_id: str | None = None,
    path: str | None = None,
    severity: Literal["ERROR", "WARNING"] = "ERROR",
) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "record_id": record_id,
        "path": path,
        "message": message,
    }


def _inspect_json_keys(
    value: Any,
    prohibited: set[str],
    max_depth: int,
    max_nodes: int,
) -> tuple[set[str], bool]:
    found: set[str] = set()
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            return found, False
        if isinstance(current, dict):
            for key, child in current.items():
                if isinstance(key, str) and key.casefold() in prohibited:
                    found.add(key.casefold())
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return found, True


def _parse_index(value: dict[str, Any], policy: dict[str, Any]) -> None:
    _exact_keys(value, _INDEX_KEYS, "index")
    if value["schema"] != INDEX_SCHEMA:
        raise AuditError("evidence index schema is unsupported")
    for field in ("manifest_sha256", "reproduction_report_sha256", "artifact_sha256"):
        if not isinstance(value[field], str) or not _SHA256.fullmatch(value[field]):
            raise AuditError(f"index.{field} is malformed")
    if value["artifact_sha256"] != _sealed_digest(value):
        raise AuditError("evidence index digest mismatch")
    if value["evidence_origin"] != "SOFTWARE_EVIDENCE_PACKAGE":
        raise AuditError("evidence index origin is unsupported")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise AuditError("evidence index hardware status must remain NOT_VERIFIED")
    records = value["records"]
    if (
        not isinstance(records, list)
        or not records
        or len(records) > policy["limits"]["max_records"]
    ):
        raise AuditError("evidence index record count is outside its bound")
    identifiers: set[str] = set()
    paths: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise AuditError(f"records[{index}] must be an object")
        _exact_keys(record, _RECORD_KEYS, f"records[{index}]")
        spec = {key: record[key] for key in _RECORD_SPEC_KEYS}
        _validate_record_spec(spec, policy, f"records[{index}]")
        if record["id"] in identifiers or record["path"] in paths:
            raise AuditError("evidence record id or path is duplicated")
        identifiers.add(record["id"])
        paths.add(record["path"])
        if (
            not isinstance(record["bytes"], int)
            or record["bytes"] < 0
            or record["bytes"] > policy["limits"]["max_artifact_bytes"]
            or not isinstance(record["sha256"], str)
            or not _SHA256.fullmatch(record["sha256"])
        ):
            raise AuditError(f"records[{index}] size or digest is malformed")
    summary = value["summary"]
    if not isinstance(summary, dict):
        raise AuditError("index summary must be an object")
    _exact_keys(summary, _SUMMARY_KEYS, "index.summary")
    if not all(isinstance(count, int) and count >= 0 for count in summary.values()):
        raise AuditError("index summary counts must be non-negative integers")
    outcomes = value["outcomes"]
    if not isinstance(outcomes, list):
        raise AuditError("index outcomes must be an array")
    for index, outcome in enumerate(outcomes):
        if not isinstance(outcome, dict):
            raise AuditError(f"outcomes[{index}] must be an object")
        _exact_keys(outcome, _OUTCOME_KEYS, f"outcomes[{index}]")


def _new_report(index: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA,
        "index_sha256": index.get("artifact_sha256", "0" * 64),
        "manifest_sha256": index.get("manifest_sha256", "0" * 64),
        "reproduction_report_sha256": index.get(
            "reproduction_report_sha256", "0" * 64
        ),
        "checked_records": 0,
        "checked_bytes": 0,
        "summary": {verdict: 0 for verdict in sorted(_SUMMARY_KEYS)},
        "outcomes": [],
        "findings": [],
        "verdict": "INCONCLUSIVE",
        "audit_scope": policy["audit_scope"],
        "evidence_origin": policy["evidence_origin"],
        "security_interpretation": policy["security_interpretation"],
        "hardware_status": policy["hardware_status"],
        "artifact_sha256": "",
    }


def _finalize_report(report: dict[str, Any]) -> dict[str, Any]:
    report["findings"] = sorted(
        report["findings"],
        key=lambda item: (
            item["severity"],
            item["code"],
            item["record_id"] or "",
            item["path"] or "",
        ),
    )
    if any(finding["severity"] == "ERROR" for finding in report["findings"]):
        report["verdict"] = "FAIL"
    elif any(finding["severity"] == "WARNING" for finding in report["findings"]):
        report["verdict"] = "INCONCLUSIVE"
    else:
        report["verdict"] = "PASS"
    report["artifact_sha256"] = _sealed_digest(report)
    return report


def audit_evidence_package(
    package_root: Path,
    index_path: Path,
    policy_path: Path,
) -> dict[str, Any]:
    """Audit completeness, integrity, non-pass preservation, and fixed secret patterns."""

    policy = load_audit_policy(policy_path)
    raw_index_sha256 = "0" * 64
    try:
        if index_path.is_file():
            raw_index_sha256 = _sha256(index_path.read_bytes())
        index = _load_json(
            index_path, policy["limits"]["max_index_bytes"], "evidence index"
        )
        _parse_index(index, policy)
    except AuditError:
        report = _new_report({}, policy)
        report["index_sha256"] = raw_index_sha256
        report["findings"].append(
            _finding("INDEX_INVALID", "evidence index failed strict parsing or digest validation")
        )
        return _finalize_report(report)

    report = _new_report(index, policy)
    records = index["records"]
    record_by_id = {record["id"]: record for record in records}
    kinds = {record["kind"] for record in records}
    for kind in policy["required_kinds"]:
        if kind not in kinds:
            report["findings"].append(
                _finding("REQUIRED_EVIDENCE_MISSING", "required evidence kind is absent")
            )

    actual_summary = {
        verdict: sum(record["verdict"] == verdict for record in records)
        for verdict in sorted(_SUMMARY_KEYS)
    }
    report["summary"] = actual_summary
    if index["summary"] != actual_summary:
        report["findings"].append(
            _finding("VERDICT_SUMMARY_MISMATCH", "record verdict counts do not match the index")
        )

    outcome_by_code = {
        outcome.get("code"): outcome
        for outcome in index["outcomes"]
        if isinstance(outcome, dict)
    }
    if set(outcome_by_code) != set(policy["required_outcome_codes"]):
        report["findings"].append(
            _finding("OUTCOME_LEDGER_INCOMPLETE", "required non-pass outcome ledger is incomplete")
        )
    for code in policy["required_outcome_codes"]:
        outcome = outcome_by_code.get(code)
        if not isinstance(outcome, dict):
            continue
        count = outcome.get("count")
        artifact_ids = outcome.get("artifact_ids")
        if (
            not isinstance(count, int)
            or count < 0
            or not isinstance(artifact_ids, list)
            or count != len(artifact_ids)
            or len(artifact_ids) != len(set(artifact_ids))
        ):
            report["findings"].append(
                _finding("OUTCOME_COUNT_MISMATCH", "non-pass outcome count is inconsistent")
            )
            continue
        for artifact_id in artifact_ids:
            record = record_by_id.get(artifact_id)
            if (
                record is None
                or code not in record["reason_codes"]
                or record["verdict"] == "PASS"
            ):
                report["findings"].append(
                    _finding(
                        "OUTCOME_REFERENCE_INVALID",
                        "non-pass outcome does not reference matching non-pass evidence",
                    )
                )
        report["outcomes"].append(
            {"code": code, "count": count, "artifact_ids": sorted(artifact_ids)}
        )

    prohibited_keys = {key.casefold() for key in policy["prohibited_keys"]}
    suffixes = tuple(suffix.casefold() for suffix in policy["prohibited_path_suffixes"])
    total_bytes = 0
    internal_links: dict[str, str] = {}
    for record in records:
        record_id = record["id"]
        relative = record["path"]
        if relative.casefold().endswith(suffixes):
            report["findings"].append(
                _finding(
                    "PROHIBITED_PATH",
                    "evidence path has a prohibited secret-bearing suffix",
                    record_id=record_id,
                    path=relative,
                )
            )
        try:
            path = _resolve_package_file(package_root, relative)
            encoded = path.read_bytes()
        except (AuditError, OSError):
            report["findings"].append(
                _finding(
                    "ARTIFACT_UNAVAILABLE",
                    "evidence artifact is missing, escaped, or unreadable",
                    record_id=record_id,
                    path=relative,
                )
            )
            continue
        total_bytes += len(encoded)
        if total_bytes > policy["limits"]["max_total_bytes"]:
            report["findings"].append(
                _finding("PACKAGE_SIZE_BOUND", "evidence package exceeds total byte bound")
            )
            break
        if len(encoded) != record["bytes"] or _sha256(encoded) != record["sha256"]:
            report["findings"].append(
                _finding(
                    "ARTIFACT_DIGEST_MISMATCH",
                    "evidence artifact size or digest does not match the index",
                    record_id=record_id,
                    path=relative,
                )
            )
            continue
        text = encoded.decode("utf-8", errors="replace")
        for pattern_id in policy["secret_pattern_ids"]:
            if _SECRET_PATTERNS[pattern_id].search(text):
                report["findings"].append(
                    _finding(
                        "SECRET_PATTERN_DETECTED",
                        "evidence matches a prohibited credential pattern",
                        record_id=record_id,
                        path=relative,
                    )
                )
        if record["content_type"] == "JSON":
            try:
                document = json.loads(encoded)
            except (UnicodeError, json.JSONDecodeError):
                report["findings"].append(
                    _finding(
                        "JSON_PARSE_ERROR",
                        "declared JSON evidence failed strict parsing",
                        record_id=record_id,
                        path=relative,
                    )
                )
                continue
            found, complete = _inspect_json_keys(
                document,
                prohibited_keys,
                policy["limits"]["max_json_depth"],
                policy["limits"]["max_json_nodes"],
            )
            if found:
                report["findings"].append(
                    _finding(
                        "PROHIBITED_KEY_DETECTED",
                        "JSON evidence contains a prohibited private-data key",
                        record_id=record_id,
                        path=relative,
                    )
                )
            if not complete:
                report["findings"].append(
                    _finding(
                        "JSON_SCAN_BOUND",
                        "JSON evidence exceeded structural scan bounds",
                        record_id=record_id,
                        path=relative,
                    )
                )
            if isinstance(document, dict) and isinstance(document.get("artifact_sha256"), str):
                internal_links[record["kind"]] = document["artifact_sha256"]
        elif record["content_type"] == "TEXT":
            try:
                encoded.decode("utf-8", errors="strict")
            except UnicodeError:
                report["findings"].append(
                    _finding(
                        "TEXT_DECODE_ERROR",
                        "declared text evidence is not valid UTF-8",
                        record_id=record_id,
                        path=relative,
                    )
                )
        report["checked_records"] += 1
        report["checked_bytes"] += len(encoded)

    if internal_links.get("MANIFEST") != index["manifest_sha256"]:
        report["findings"].append(
            _finding("MANIFEST_LINK_MISMATCH", "manifest internal digest does not match the index")
        )
    if internal_links.get("REPRODUCTION_REPORT") != index["reproduction_report_sha256"]:
        report["findings"].append(
            _finding(
                "REPRODUCTION_LINK_MISMATCH",
                "reproduction report internal digest does not match the index",
            )
        )
    return _finalize_report(report)


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def render_audit_markdown(report: dict[str, Any]) -> str:
    """Render a deterministic human-readable audit without raw evidence values."""

    lines = [
        "# QuotientSeal Evidence Audit",
        "",
        f"- verdict: **{report['verdict']}**",
        f"- checked records: {report['checked_records']}",
        f"- checked bytes: {report['checked_bytes']}",
        f"- audit scope: `{report['audit_scope']}`",
        f"- hardware status: `{report['hardware_status']}`",
        f"- report SHA-256: `{report['artifact_sha256']}`",
        "",
        "## Verdict counts",
        "",
        "| PASS | FAIL | INCONCLUSIVE | NOT_RUN |",
        "|---:|---:|---:|---:|",
        "| {PASS} | {FAIL} | {INCONCLUSIVE} | {NOT_RUN} |".format(**report["summary"]),
        "",
        "## Explicit non-pass ledger",
        "",
        "| Code | Count |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {_markdown_cell(outcome['code'])} | {outcome['count']} |"
        for outcome in report["outcomes"]
    )
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings in the bounded taxonomy.")
    else:
        lines.extend(
            f"- **{finding['severity']} / {finding['code']}**: {finding['message']}"
            for finding in report["findings"]
        )
    lines.extend(
        [
            "",
            "## Claim boundary",
            "",
            "This is a bounded structural and pattern audit, not a security verdict.",
            "Polar Verity Sense hardware remains NOT_VERIFIED.",
            "",
        ]
    )
    return "\n".join(lines)


def write_audit_report(report: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    """Atomically write canonical JSON and deterministic Markdown audit artifacts."""

    for path, encoded in (
        (json_path, canonical_json(report)),
        (markdown_path, render_audit_markdown(report).encode("utf-8")),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_bytes(encoded)
        temporary.replace(path)

