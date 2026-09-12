"""Fail-closed GO-candidate, PIVOT, or BLOCKED gate for K7 scalability."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Final

import yaml

from noticer_core.evaluation.scalability_contract import BACKENDS, TARGET, OutcomeStatus

SCHEMA: Final = "noticer.k7.scalability-gate.v1"
POLICY_SCHEMA: Final = "noticer.k7.scalability-gate-policy.v1"
HASH_DOMAIN: Final = b"NOTICER_K7_SCALABILITY_GATE_V1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_BINDINGS: Final = frozenset(
    {
        "corpus_sha256",
        "split_sha256",
        "bound_sha256",
        "backend_sha256",
        "result_sha256",
    }
)
POLICY: Final = {
    "required_grid_status": "COMPLETE",
    "minimum_completed_backends": 1,
    "pivot_only_statuses": ["TIMEOUT", "MEMORY_LIMIT"],
    "blocked_statuses": [
        "SOLVER_UNKNOWN",
        "PROCESS_FAILURE",
        "INVALID_CASE",
        "NOT_RUN",
    ],
    "non_monotonic_policy": "BLOCK",
    "missing_backend_policy": "BLOCK",
    "target_gate": TARGET,
    "deployment_generalization": "FORBIDDEN",
}


class ScalabilityGateError(ValueError):
    """Gate inputs or policy are malformed, unbound, or internally inconsistent."""


class GateDecision(StrEnum):
    """GO is intentionally only a research continuation candidate."""

    GO_CANDIDATE = "GO_CANDIDATE"
    PIVOT = "PIVOT"
    BLOCKED = "BLOCKED"


def load_gate_policy(path: Path) -> dict[str, object]:
    """Load the frozen gate policy without accepting post-result changes."""

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if type(value) is not dict or set(value) != {"schema", "version", "state", "policy"}:
        raise ScalabilityGateError("gate policy fields differ")
    if value["schema"] != POLICY_SCHEMA or value["version"] != 1 or value["state"] != "FROZEN":
        raise ScalabilityGateError("unsupported or unfrozen gate policy")
    if value["policy"] != POLICY:
        raise ScalabilityGateError("gate policy differs from frozen v1")
    return value


def build_gate_manifest(
    frontier_report: Mapping[str, object],
    target_outcomes: Mapping[str, OutcomeStatus],
    bindings: Mapping[str, str],
    *,
    policy: Mapping[str, object],
) -> dict[str, object]:
    """Apply the frozen non-compensatory decision rule to 12x8x64 outcomes."""

    if policy.get("schema") != POLICY_SCHEMA or policy.get("policy") != POLICY:
        raise ScalabilityGateError("unverified gate policy")
    if frontier_report.get("schema") != "noticer.k7.scalability-frontier.v1":
        raise ScalabilityGateError("unsupported frontier report")
    _verify_frontier_digest(frontier_report)
    if set(bindings) != REQUIRED_BINDINGS or any(
        _SHA256.fullmatch(value) is None for value in bindings.values()
    ):
        raise ScalabilityGateError("all corpus/split/bound/backend/result digests are required")
    backend_ids = {backend for backend, _reduction in BACKENDS}
    if set(target_outcomes) != backend_ids:
        decision = GateDecision.BLOCKED
        reasons = ["TARGET_BACKEND_MISSING"]
        normalized_outcomes = {
            backend: target_outcomes.get(backend, OutcomeStatus.NOT_RUN).value
            for backend in sorted(backend_ids)
        }
    else:
        normalized_outcomes = {
            backend: target_outcomes[backend].value for backend in sorted(backend_ids)
        }
        decision, reasons = _decide(frontier_report, target_outcomes)

    counts = Counter(normalized_outcomes.values())
    manifest: dict[str, object] = {
        "schema": SCHEMA,
        "policy_schema": POLICY_SCHEMA,
        "decision": decision.value,
        "reasons": reasons,
        "target_gate": dict(TARGET),
        "target_outcomes": normalized_outcomes,
        "target_summary": {status.value: counts[status.value] for status in OutcomeStatus},
        "bindings": dict(sorted(bindings.items())),
        "frontier_sha256": frontier_report["artifact_sha256"],
        "minimum_completed_backends": POLICY["minimum_completed_backends"],
        "deployment_generalization": "FORBIDDEN",
        "hardware_status": "NOT_VERIFIED",
        "security_interpretation": "RESEARCH_CONTINUATION_GATE_ONLY",
    }
    manifest["artifact_sha256"] = _manifest_digest(manifest)
    return manifest


def _decide(
    frontier: Mapping[str, object], outcomes: Mapping[str, OutcomeStatus]
) -> tuple[GateDecision, list[str]]:
    if frontier.get("grid_status") != "COMPLETE" or frontier.get("missing_measured_runs") != 0:
        return GateDecision.BLOCKED, ["GRID_INCOMPLETE"]
    warnings = frontier.get("non_monotonic_warnings")
    if type(warnings) is not list:
        raise ScalabilityGateError("frontier warnings are malformed")
    if warnings:
        return GateDecision.BLOCKED, ["NON_MONOTONIC_RESULT"]
    blocked = {OutcomeStatus(value) for value in POLICY["blocked_statuses"]}
    blocked_observed = sorted(
        {status.value for status in outcomes.values() if status in blocked}
    )
    if blocked_observed:
        return GateDecision.BLOCKED, [f"TARGET_{status}" for status in blocked_observed]
    completed = sum(status is OutcomeStatus.COMPLETED for status in outcomes.values())
    if completed >= POLICY["minimum_completed_backends"]:
        return GateDecision.GO_CANDIDATE, ["TARGET_COMPLETED_BY_AT_LEAST_ONE_BACKEND"]
    pivot = {OutcomeStatus(value) for value in POLICY["pivot_only_statuses"]}
    if outcomes and all(status in pivot for status in outcomes.values()):
        return GateDecision.PIVOT, ["ALL_BACKENDS_RESOURCE_NONPRACTICAL"]
    return GateDecision.BLOCKED, ["TARGET_EVIDENCE_UNCLASSIFIED"]


def _verify_frontier_digest(report: Mapping[str, object]) -> None:
    claimed = report.get("artifact_sha256")
    if type(claimed) is not str or _SHA256.fullmatch(claimed) is None:
        raise ScalabilityGateError("frontier digest is missing")
    unsigned = dict(report)
    unsigned.pop("artifact_sha256")
    actual = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if actual != claimed:
        raise ScalabilityGateError("frontier digest mismatch")


def _manifest_digest(manifest: Mapping[str, object]) -> str:
    unsigned = dict(manifest)
    unsigned.pop("artifact_sha256", None)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(HASH_DOMAIN + encoded).hexdigest()
