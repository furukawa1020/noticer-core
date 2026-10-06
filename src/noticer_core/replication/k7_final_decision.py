"""Frozen, non-compensatory GO/PIVOT/KILL decision for the K7 program."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from noticer_core.evaluation.k7_research_contract import (
    build_research_manifest,
    load_research_contract,
)
from noticer_core.replication.manifest import canonical_json

POLICY_SCHEMA: Final = "noticer-core.k7-final-decision-policy.v1"
EVIDENCE_SCHEMA: Final = "noticer-core.k7-final-evidence.v1"
REPORT_SCHEMA: Final = "noticer-core.k7-final-decision.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-final-decision/v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POLICY_KEYS: Final = {
    "schema",
    "frozen_contract_sha256",
    "frozen_gate_registry_sha256",
    "decision_precedence",
    "missing_evidence_action",
    "criteria",
    "rejection_arguments",
    "priority_wording",
    "security_interpretation",
    "hardware_status",
}


class K7FinalDecisionError(ValueError):
    """Raised when final policy or evidence violates the frozen contract."""


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def load_policy(policy_path: Path, contract_path: Path) -> dict[str, Any]:
    """Load policy only when its frozen contract and gate hashes still match."""

    try:
        value = json.loads(policy_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7FinalDecisionError("final policy is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != _POLICY_KEYS:
        raise K7FinalDecisionError("final policy fields are invalid")
    if value["schema"] != POLICY_SCHEMA:
        raise K7FinalDecisionError("final policy schema is unsupported")
    manifest = build_research_manifest(load_research_contract(contract_path))
    if value["frozen_contract_sha256"] != manifest["contract_sha256"]:
        raise K7FinalDecisionError("frozen contract digest mismatch")
    if value["frozen_gate_registry_sha256"] != manifest["gate_registry_sha256"]:
        raise K7FinalDecisionError("frozen gate registry digest mismatch")
    if value["decision_precedence"] != ["KILL", "PIVOT", "GO"]:
        raise K7FinalDecisionError("decision precedence must remain KILL, PIVOT, GO")
    if value["missing_evidence_action"] != "PIVOT":
        raise K7FinalDecisionError("missing evidence must produce PIVOT")
    criteria = value["criteria"]
    if not isinstance(criteria, dict) or set(criteria) != {"GO", "PIVOT", "KILL"}:
        raise K7FinalDecisionError("criteria categories are invalid")
    all_criteria: list[str] = []
    for category in ("GO", "PIVOT", "KILL"):
        entries = criteria[category]
        if not isinstance(entries, list) or not entries or not all(
            isinstance(item, str) and item for item in entries
        ):
            raise K7FinalDecisionError(f"{category} criteria are invalid")
        all_criteria.extend(entries)
    if len(all_criteria) != len(set(all_criteria)):
        raise K7FinalDecisionError("decision criteria must be globally unique")
    arguments = value["rejection_arguments"]
    if not isinstance(arguments, list) or len(arguments) < 25:
        raise K7FinalDecisionError("at least 25 rejection arguments are required")
    expected_ids = [f"R{index:02d}" for index in range(1, len(arguments) + 1)]
    if [item.get("id") for item in arguments] != expected_ids:
        raise K7FinalDecisionError("rejection argument ids must be contiguous")
    if any(
        not isinstance(item, dict)
        or set(item) != {"id", "class", "argument"}
        or item["class"] not in {"SURVIVE", "PIVOT", "FATAL"}
        or not isinstance(item["argument"], str)
        or not item["argument"]
        for item in arguments
    ):
        raise K7FinalDecisionError("rejection argument record is invalid")
    allowed_wording = (
        "to the best of our literature review, "
        "we found no prior work combining these exact semantics"
    )
    if value["priority_wording"] != allowed_wording:
        raise K7FinalDecisionError("priority wording exceeds the reviewed evidence")
    if value["security_interpretation"] != "BOUNDED_RESEARCH_DECISION_NOT_SECURITY_PROOF":
        raise K7FinalDecisionError("security interpretation is invalid")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise K7FinalDecisionError("hardware status must remain NOT_VERIFIED")
    return value


def blank_evidence(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return explicit unknown evidence; this must never produce GO."""

    criterion_ids = [
        item for category in ("GO", "PIVOT", "KILL") for item in policy["criteria"][category]
    ]
    evidence: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "criteria": {
            item: {"artifact_sha256": None, "observed": None} for item in criterion_ids
        },
        "rejection_arguments": {
            item["id"]: {"artifact_sha256": None, "status": "OPEN"}
            for item in policy["rejection_arguments"]
        },
    }
    evidence["evidence_digest"] = _digest(evidence)
    return evidence


def _validate_evidence(policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    if set(evidence) != {"schema", "criteria", "rejection_arguments", "evidence_digest"}:
        raise K7FinalDecisionError("final evidence fields are invalid")
    if evidence["schema"] != EVIDENCE_SCHEMA:
        raise K7FinalDecisionError("final evidence schema is invalid")
    unsigned = copy.deepcopy(dict(evidence))
    claimed = unsigned.pop("evidence_digest")
    if claimed != _digest(unsigned):
        raise K7FinalDecisionError("final evidence digest mismatch")
    expected_criteria = {
        item for category in ("GO", "PIVOT", "KILL") for item in policy["criteria"][category]
    }
    if set(evidence["criteria"]) != expected_criteria:
        raise K7FinalDecisionError("criterion evidence inventory is incomplete")
    for record in evidence["criteria"].values():
        if not isinstance(record, dict) or set(record) != {"artifact_sha256", "observed"}:
            raise K7FinalDecisionError("criterion evidence record is invalid")
        if record["observed"] not in {True, False, None}:
            raise K7FinalDecisionError("criterion observation is invalid")
        digest = record["artifact_sha256"]
        if digest is not None and (
            not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
        ):
            raise K7FinalDecisionError("criterion artifact digest is invalid")
        if record["observed"] is not None and digest is None:
            raise K7FinalDecisionError("observed criterion requires an artifact digest")
    expected_arguments = {item["id"] for item in policy["rejection_arguments"]}
    if set(evidence["rejection_arguments"]) != expected_arguments:
        raise K7FinalDecisionError("rejection evidence inventory is incomplete")
    for record in evidence["rejection_arguments"].values():
        if not isinstance(record, dict) or set(record) != {"artifact_sha256", "status"}:
            raise K7FinalDecisionError("rejection evidence record is invalid")
        if record["status"] not in {"ADDRESSED", "OPEN", "TRIGGERED"}:
            raise K7FinalDecisionError("rejection evidence status is invalid")
        digest = record["artifact_sha256"]
        if record["status"] != "OPEN" and (
            not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
        ):
            raise K7FinalDecisionError("resolved rejection requires an artifact digest")


def decide(policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Apply frozen KILL-first, non-compensatory final decision semantics."""

    _validate_evidence(policy, evidence)
    criteria = evidence["criteria"]
    kill_reasons = [
        item for item in policy["criteria"]["KILL"] if criteria[item]["observed"] is True
    ]
    pivot_reasons = [
        item for item in policy["criteria"]["PIVOT"] if criteria[item]["observed"] is True
    ]
    unmet_go = [item for item in policy["criteria"]["GO"] if criteria[item]["observed"] is not True]
    argument_classes = {item["id"]: item["class"] for item in policy["rejection_arguments"]}
    argument_statuses = evidence["rejection_arguments"]
    fatal_triggered = [
        item for item, kind in argument_classes.items()
        if kind == "FATAL" and argument_statuses[item]["status"] == "TRIGGERED"
    ]
    unresolved_arguments = [
        item for item in argument_classes if argument_statuses[item]["status"] == "OPEN"
    ]
    triggered_pivots = [
        item for item, kind in argument_classes.items()
        if kind == "PIVOT" and argument_statuses[item]["status"] == "TRIGGERED"
    ]
    if kill_reasons or fatal_triggered:
        decision = "KILL"
    elif pivot_reasons or unmet_go or unresolved_arguments or triggered_pivots:
        decision = "PIVOT"
    else:
        decision = "GO"
    statuses = Counter(record["status"] for record in argument_statuses.values())
    report: dict[str, Any] = {
        "decision": decision,
        "evidence_digest": evidence["evidence_digest"],
        "fatal_rejections_triggered": sorted(fatal_triggered),
        "hardware_status": "NOT_VERIFIED",
        "kill_criteria_triggered": sorted(kill_reasons),
        "policy_digest": _digest(policy),
        "priority_wording": policy["priority_wording"],
        "rejection_argument_counts": {
            "ADDRESSED": statuses["ADDRESSED"],
            "OPEN": statuses["OPEN"],
            "TRIGGERED": statuses["TRIGGERED"],
            "TOTAL": len(argument_statuses),
        },
        "schema": REPORT_SCHEMA,
        "security_interpretation": "BOUNDED_RESEARCH_DECISION_NOT_SECURITY_PROOF",
        "triggered_pivot_arguments": sorted(triggered_pivots),
        "unmet_go_criteria": sorted(unmet_go),
        "unresolved_rejection_arguments": sorted(unresolved_arguments),
    }
    report["report_digest"] = _digest(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Create blank evidence or evaluate the final K7 decision."""

    parser = argparse.ArgumentParser(description="K7 frozen GO/PIVOT/KILL gateを評価する")
    parser.add_argument("command", choices=("blank-evidence", "decide"))
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("replication/k7_final_decision_policy_v1.json"),
    )
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path("configs/quotient_forge/k7_research.yaml"),
    )
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    policy = load_policy(args.policy, args.contract)
    if args.command == "blank-evidence":
        output = blank_evidence(policy)
        exit_code = 0
    else:
        if args.evidence is None:
            raise K7FinalDecisionError("decide requires --evidence")
        output = decide(policy, json.loads(args.evidence.read_bytes()))
        exit_code = 0 if output["decision"] == "GO" else 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(output))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
