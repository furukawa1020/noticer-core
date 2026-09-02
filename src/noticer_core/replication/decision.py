"""Predeclared, non-compensatory Go/Pivot/Kill decision gate."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from noticer_core.replication.manifest import canonical_json

JsonObject = dict[str, Any]

_POLICY_SCHEMA: Final = "quotient-seal-decision-policy/v1"
_INPUT_SCHEMA: Final = "quotient-seal-decision-input/v1"
_REPORT_SCHEMA: Final = "quotient-seal-decision/v1"
_SCOPE: Final = "QUOTIENTSEAL_SOFTWARE_EVALUATION"
_MAX_DOCUMENT_BYTES: Final = 2 * 1024 * 1024
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CODE_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

AXES: Final = (
    "manifest",
    "reproduction",
    "evidence_audit",
    "security",
    "utility",
    "mutation",
    "engine",
    "attack",
    "performance",
    "ablation",
)
STATUSES: Final = (
    "PASS",
    "FAIL",
    "INCONCLUSIVE",
    "MISSING",
    "NOT_RUN",
    "UNSUPPORTED",
)
_THRESHOLD_KEYS: Final = {
    ("security", "invalid_cases"),
    ("utility", "retention_ratio"),
    ("mutation", "critical_escaped_mutants"),
    ("engine", "disagreements"),
    ("attack", "identity_advantage"),
    ("performance", "overhead_ratio"),
}
_BOUNDARIES: Final = {
    "PREDECLARED_RULE_EVALUATION",
    "SOFTWARE_DECISION_GATE",
    "NOT_A_PROOF",
    "NOT_VERIFIED",
}


class DecisionError(ValueError):
    """Raised when a decision contract or its integrity check is invalid."""


def _reject_constant(value: str) -> None:
    raise DecisionError(f"non-finite JSON number is forbidden: {value}")


def _load_document(
    source: Mapping[str, object] | Path,
    *,
    label: str,
) -> JsonObject:
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise DecisionError(f"cannot read {label}: {source}") from exc
        if len(raw) > _MAX_DOCUMENT_BYTES:
            raise DecisionError(f"{label} exceeds {_MAX_DOCUMENT_BYTES} bytes")
        try:
            document = json.loads(
                raw.decode("utf-8"),
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DecisionError(f"{label} is not strict UTF-8 JSON") from exc
    elif isinstance(source, Mapping):
        try:
            encoded = json.dumps(source, allow_nan=False)
            document = json.loads(encoded, parse_constant=_reject_constant)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DecisionError(f"{label} is not JSON-compatible") from exc
    else:
        raise DecisionError(f"{label} must be a mapping or pathlib.Path")
    if not isinstance(document, dict):
        raise DecisionError(f"{label} root must be an object")
    return document


def _exact_keys(value: JsonObject, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise DecisionError(
            f"{label} fields differ; missing={missing}, unknown={unknown}"
        )


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise DecisionError(f"{label} must be an object")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DecisionError(f"{label} must be a string array")
    return value


def _finite_number(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionError(f"{label} must be a number")
    if not math.isfinite(value):
        raise DecisionError(f"{label} must be finite")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_decision_policy(source: Mapping[str, object] | Path) -> JsonObject:
    """Load and strictly validate a versioned decision policy."""

    policy = _load_document(source, label="decision policy")
    _exact_keys(
        policy,
        {
            "schema_version",
            "decision_precedence",
            "allowed_statuses",
            "required_axes",
            "fail_actions",
            "thresholds",
            "nonpass_action",
            "go_requires_all_pass",
            "boundaries",
        },
        "decision policy",
    )
    if policy["schema_version"] != _POLICY_SCHEMA:
        raise DecisionError("unsupported decision policy schema")
    if policy["decision_precedence"] != ["KILL", "PIVOT", "GO"]:
        raise DecisionError("decision precedence must be KILL, PIVOT, GO")
    if _string_list(policy["allowed_statuses"], "allowed_statuses") != list(
        STATUSES
    ):
        raise DecisionError("allowed statuses differ from the v1 contract")
    if _string_list(policy["required_axes"], "required_axes") != list(AXES):
        raise DecisionError("required axes differ from the v1 contract")
    if policy["nonpass_action"] != "PIVOT":
        raise DecisionError("nonpass_action must be PIVOT")
    if policy["go_requires_all_pass"] is not True:
        raise DecisionError("GO must require PASS on every axis")

    fail_actions = _object(policy["fail_actions"], "fail_actions")
    _exact_keys(fail_actions, set(AXES), "fail_actions")
    if any(action not in {"KILL", "PIVOT"} for action in fail_actions.values()):
        raise DecisionError("FAIL actions may only be KILL or PIVOT")

    thresholds = policy["thresholds"]
    if not isinstance(thresholds, list):
        raise DecisionError("thresholds must be an array")
    seen: set[tuple[str, str]] = set()
    for index, raw_threshold in enumerate(thresholds):
        threshold = _object(raw_threshold, f"thresholds[{index}]")
        _exact_keys(
            threshold,
            {
                "axis",
                "metric",
                "operator",
                "limit",
                "on_violation",
                "reason_code",
            },
            f"thresholds[{index}]",
        )
        axis = threshold["axis"]
        metric = threshold["metric"]
        if not isinstance(axis, str) or not isinstance(metric, str):
            raise DecisionError("threshold axis and metric must be strings")
        key = (axis, metric)
        if key not in _THRESHOLD_KEYS or key in seen:
            raise DecisionError(f"unexpected or duplicate threshold: {key}")
        seen.add(key)
        if threshold["operator"] not in {"MAX", "MIN"}:
            raise DecisionError("threshold operator must be MAX or MIN")
        _finite_number(threshold["limit"], f"thresholds[{index}].limit")
        if threshold["on_violation"] not in {"KILL", "PIVOT"}:
            raise DecisionError("threshold violation may not produce GO")
        code = threshold["reason_code"]
        if not isinstance(code, str) or _CODE_RE.fullmatch(code) is None:
            raise DecisionError("threshold reason_code is invalid")
    if seen != _THRESHOLD_KEYS:
        raise DecisionError("the v1 threshold set is incomplete")

    boundaries = _string_list(policy["boundaries"], "boundaries")
    if len(boundaries) != len(set(boundaries)) or not _BOUNDARIES.issubset(
        boundaries
    ):
        raise DecisionError("required decision boundaries are missing")
    return policy


def load_decision_input(
    source: Mapping[str, object] | Path,
    policy: Mapping[str, object] | Path,
) -> JsonObject:
    """Load and strictly validate a decision input against a policy."""

    checked_policy = load_decision_policy(policy)
    document = _load_document(source, label="decision input")
    _exact_keys(
        document,
        {
            "schema_version",
            "run_id",
            "scope",
            "source_commit",
            "hardware_status",
            "artifacts",
            "axes",
        },
        "decision input",
    )
    if document["schema_version"] != _INPUT_SCHEMA:
        raise DecisionError("unsupported decision input schema")
    run_id = document["run_id"]
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise DecisionError("run_id is invalid")
    if document["scope"] != _SCOPE:
        raise DecisionError("decision input scope is invalid")
    source_commit = document["source_commit"]
    if not isinstance(source_commit, str) or _COMMIT_RE.fullmatch(source_commit) is None:
        raise DecisionError("source_commit must be a full lowercase Git SHA")
    if document["hardware_status"] != "NOT_VERIFIED":
        raise DecisionError("v1 is a software-only gate and must remain NOT_VERIFIED")

    artifacts = _object(document["artifacts"], "artifacts")
    _exact_keys(
        artifacts,
        {"manifest_sha256", "reproduction_sha256", "evidence_audit_sha256"},
        "artifacts",
    )
    for name, digest in artifacts.items():
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise DecisionError(f"artifacts.{name} is not a SHA-256 digest")

    axes = _object(document["axes"], "axes")
    _exact_keys(axes, set(AXES), "axes")
    expected_metrics: dict[str, set[str]] = {axis: set() for axis in AXES}
    for threshold in checked_policy["thresholds"]:
        expected_metrics[threshold["axis"]].add(threshold["metric"])

    for axis_name in AXES:
        axis = _object(axes[axis_name], f"axes.{axis_name}")
        _exact_keys(
            axis,
            {"status", "artifact_sha256", "reason_codes", "metrics"},
            f"axes.{axis_name}",
        )
        if axis["status"] not in STATUSES:
            raise DecisionError(f"axes.{axis_name}.status is invalid")
        digest = axis["artifact_sha256"]
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise DecisionError(f"axes.{axis_name}.artifact_sha256 is invalid")
        codes = _string_list(axis["reason_codes"], f"axes.{axis_name}.reason_codes")
        if len(codes) != len(set(codes)) or any(
            _CODE_RE.fullmatch(code) is None for code in codes
        ):
            raise DecisionError(f"axes.{axis_name}.reason_codes is invalid")
        if axis["status"] != "PASS" and not codes:
            raise DecisionError(f"axes.{axis_name} non-PASS status needs a reason")
        metrics = _object(axis["metrics"], f"axes.{axis_name}.metrics")
        _exact_keys(metrics, expected_metrics[axis_name], f"axes.{axis_name}.metrics")
        for metric_name, metric_value in metrics.items():
            number = _finite_number(
                metric_value,
                f"axes.{axis_name}.metrics.{metric_name}",
            )
            if number < 0:
                raise DecisionError("decision metrics must be non-negative")
        if "retention_ratio" in metrics and metrics["retention_ratio"] > 1:
            raise DecisionError("retention_ratio must be within [0, 1]")
        for count_name in {
            "invalid_cases",
            "critical_escaped_mutants",
            "disagreements",
        }:
            if count_name in metrics and not isinstance(metrics[count_name], int):
                raise DecisionError(f"{count_name} must be an integer")

    digest_links = {
        "manifest_sha256": "manifest",
        "reproduction_sha256": "reproduction",
        "evidence_audit_sha256": "evidence_audit",
    }
    for artifact_name, axis_name in digest_links.items():
        if artifacts[artifact_name] != axes[axis_name]["artifact_sha256"]:
            raise DecisionError(f"{artifact_name} does not match its evidence axis")
    return document


def _violates(observed: int | float, operator: str, limit: int | float) -> bool:
    if operator == "MAX":
        return observed > limit
    return observed < limit


def evaluate_decision(
    decision_input: Mapping[str, object] | Path,
    policy: Mapping[str, object] | Path,
) -> JsonObject:
    """Evaluate GO, PIVOT, or KILL without cross-axis compensation."""

    checked_policy = load_decision_policy(policy)
    checked_input = load_decision_input(decision_input, checked_policy)
    policy_sha256 = _sha256(canonical_json(checked_policy))
    input_sha256 = _sha256(canonical_json(checked_input))
    reasons: list[JsonObject] = []
    axis_results: list[JsonObject] = []
    thresholds_by_axis: dict[str, list[JsonObject]] = {axis: [] for axis in AXES}
    for threshold in checked_policy["thresholds"]:
        thresholds_by_axis[threshold["axis"]].append(threshold)

    for axis_name in AXES:
        axis = checked_input["axes"][axis_name]
        axis_reasons: list[JsonObject] = []
        status = axis["status"]
        if status == "FAIL":
            axis_reasons.append(
                {
                    "action": checked_policy["fail_actions"][axis_name],
                    "axis": axis_name,
                    "code": f"{axis_name.upper()}_STATUS_FAIL",
                    "expected": "PASS",
                    "observed": "FAIL",
                    "evidence_reason_codes": axis["reason_codes"],
                }
            )
        elif status != "PASS":
            axis_reasons.append(
                {
                    "action": checked_policy["nonpass_action"],
                    "axis": axis_name,
                    "code": f"{axis_name.upper()}_STATUS_{status}",
                    "expected": "PASS",
                    "observed": status,
                    "evidence_reason_codes": axis["reason_codes"],
                }
            )

        checks: list[JsonObject] = []
        for threshold in thresholds_by_axis[axis_name]:
            observed = axis["metrics"][threshold["metric"]]
            violated = _violates(
                observed,
                threshold["operator"],
                threshold["limit"],
            )
            checks.append(
                {
                    "metric": threshold["metric"],
                    "operator": threshold["operator"],
                    "limit": threshold["limit"],
                    "observed": observed,
                    "passed": not violated,
                }
            )
            if violated:
                axis_reasons.append(
                    {
                        "action": threshold["on_violation"],
                        "axis": axis_name,
                        "code": threshold["reason_code"],
                        "expected": {
                            "operator": threshold["operator"],
                            "limit": threshold["limit"],
                        },
                        "observed": observed,
                        "evidence_reason_codes": axis["reason_codes"],
                    }
                )
        reasons.extend(axis_reasons)
        effects = {reason["action"] for reason in axis_reasons}
        effect = "KILL" if "KILL" in effects else "PIVOT" if effects else "CLEAR"
        axis_results.append(
            {
                "axis": axis_name,
                "status": status,
                "effect": effect,
                "artifact_sha256": axis["artifact_sha256"],
                "threshold_checks": checks,
            }
        )

    rank = {name: index for index, name in enumerate(checked_policy["decision_precedence"])}
    axis_rank = {name: index for index, name in enumerate(AXES)}
    reasons.sort(key=lambda item: (rank[item["action"]], axis_rank[item["axis"]], item["code"]))
    actions = {reason["action"] for reason in reasons}
    decision = next(
        (
            candidate
            for candidate in checked_policy["decision_precedence"]
            if candidate in actions
        ),
        "GO",
    )

    sensitivity: list[JsonObject] = []
    for axis_name in AXES:
        sensitivity.append(
            {
                "assumption": "ALL_OTHER_GATES_PASS",
                "condition": f"{axis_name}.status=FAIL",
                "decision": checked_policy["fail_actions"][axis_name],
            }
        )
        sensitivity.append(
            {
                "assumption": "ALL_OTHER_GATES_PASS",
                "condition": f"{axis_name}.status=INCONCLUSIVE",
                "decision": checked_policy["nonpass_action"],
            }
        )
    for threshold in checked_policy["thresholds"]:
        sensitivity.append(
            {
                "assumption": "ALL_OTHER_GATES_PASS",
                "condition": (
                    f"{threshold['axis']}.{threshold['metric']} "
                    f"violates {threshold['operator']} {threshold['limit']}"
                ),
                "decision": threshold["on_violation"],
            }
        )

    falsification_conditions = sorted(
        {
            reason["code"]
            for reason in reasons
            if reason["action"] == "KILL"
        }
        | {
            f"{axis.upper()}_STATUS_FAIL"
            for axis, action in checked_policy["fail_actions"].items()
            if action == "KILL"
        }
        | {
            threshold["reason_code"]
            for threshold in checked_policy["thresholds"]
            if threshold["on_violation"] == "KILL"
        }
    )
    decision_id = _sha256(
        f"{_REPORT_SCHEMA}\0{policy_sha256}\0{input_sha256}".encode("ascii")
    )
    body: JsonObject = {
        "schema_version": _REPORT_SCHEMA,
        "decision_id": decision_id,
        "scope": checked_input["scope"],
        "run_id": checked_input["run_id"],
        "source_commit": checked_input["source_commit"],
        "hardware_status": checked_input["hardware_status"],
        "policy_sha256": policy_sha256,
        "input_sha256": input_sha256,
        "decision": decision,
        "decision_precedence": checked_policy["decision_precedence"],
        "aggregation": "NON_COMPENSATORY",
        "axis_results": axis_results,
        "reasons": reasons,
        "sensitivity": sensitivity,
        "falsification_conditions": falsification_conditions,
        "boundaries": checked_policy["boundaries"],
    }
    report_sha256 = _sha256(canonical_json(body))
    return {
        **body,
        "integrity": {
            "algorithm": "SHA-256",
            "coverage": "ALL_REPORT_FIELDS_EXCEPT_INTEGRITY",
            "report_sha256": report_sha256,
        },
    }


def verify_decision_report(report: Mapping[str, object]) -> None:
    """Raise ``DecisionError`` when a report is malformed or was changed."""

    document = _load_document(report, label="decision report")
    expected_fields = {
        "schema_version",
        "decision_id",
        "scope",
        "run_id",
        "source_commit",
        "hardware_status",
        "policy_sha256",
        "input_sha256",
        "decision",
        "decision_precedence",
        "aggregation",
        "axis_results",
        "reasons",
        "sensitivity",
        "falsification_conditions",
        "boundaries",
        "integrity",
    }
    _exact_keys(document, expected_fields, "decision report")
    if document["schema_version"] != _REPORT_SCHEMA:
        raise DecisionError("unsupported decision report schema")
    if document["decision"] not in {"GO", "PIVOT", "KILL"}:
        raise DecisionError("decision report has an invalid verdict")
    integrity = _object(document.pop("integrity"), "decision report integrity")
    _exact_keys(
        integrity,
        {"algorithm", "coverage", "report_sha256"},
        "decision report integrity",
    )
    if integrity["algorithm"] != "SHA-256" or integrity["coverage"] != (
        "ALL_REPORT_FIELDS_EXCEPT_INTEGRITY"
    ):
        raise DecisionError("decision report integrity contract is invalid")
    expected = _sha256(canonical_json(document))
    if integrity["report_sha256"] != expected:
        raise DecisionError("decision report SHA-256 mismatch")
    expected_id = _sha256(
        (
            f"{_REPORT_SCHEMA}\0{document['policy_sha256']}\0"
            f"{document['input_sha256']}"
        ).encode("ascii")
    )
    if document["decision_id"] != expected_id:
        raise DecisionError("decision_id does not match policy and input digests")


def write_decision_report(report: Mapping[str, object], path: Path) -> None:
    """Write a verified decision report as canonical UTF-8 JSON."""

    verify_decision_report(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(report) + b"\n")


def render_decision_markdown(report: Mapping[str, object]) -> str:
    """Render a concise deterministic human-readable decision record."""

    verify_decision_report(report)
    reasons = report["reasons"]
    lines = [
        "# QuotientSeal Go / Pivot / Kill Decision",
        "",
        f"- Decision: **{report['decision']}**",
        f"- Run: `{report['run_id']}`",
        f"- Source: `{report['source_commit']}`",
        f"- Hardware: `{report['hardware_status']}`",
        f"- Aggregation: `{report['aggregation']}`",
        f"- Report SHA-256: `{report['integrity']['report_sha256']}`",
        "",
        "## Reasons",
        "",
    ]
    if reasons:
        for reason in reasons:
            lines.append(
                f"- `{reason['action']}` / `{reason['axis']}` / `{reason['code']}`"
            )
    else:
        lines.append("- No blocking condition was observed under this policy.")
    lines.extend(["", "## Boundaries", ""])
    lines.extend(f"- `{boundary}`" for boundary in report["boundaries"])
    return "\n".join(lines) + "\n"
