"""Append-only safety interlock ledger for K5 Tier D and S3 ceremonies."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

SCHEMA = "noticer.k5.hardware_safety_ledger.v1"
DOMAIN = b"NOTICER-K5-HARDWARE-SAFETY-LEDGER-V1\x00"
GENESIS = "0" * 64
EVENT_KINDS = frozenset({"START", "ACTION", "REJECTION", "INCIDENT", "OPERATOR_ABORT", "STOP"})
TERMINAL_KINDS = frozenset({"OPERATOR_ABORT", "STOP"})
PLAN_FIELDS = frozenset(
    {
        "schema",
        "tier",
        "provenance",
        "preflight_digest",
        "private_bundle_sha256",
        "harmless_fixture_confirmed",
        "safety_protocol_approved",
        "stop_conditions_commitment_sha256",
        "dangerous_light_source_present",
        "scenario_approved",
    }
)
EVENT_FIELDS = frozenset(
    {
        "sequence",
        "kind",
        "monotonic_ns",
        "authorized_action_delta",
        "unauthorized_action_delta",
        "incident_code",
        "previous_digest",
        "digest",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INCIDENT = re.compile(r"^(NONE|[A-Z][A-Z0-9_]{0,31})$")


class SafetyLedgerError(ValueError):
    """A fail-closed hardware safety ledger error."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _require_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SafetyLedgerError(f"{field} must be lowercase SHA-256")
    return value


def validate_plan(plan: Mapping[str, Any]) -> None:
    """Validate immutable safety gates before a physical or fixture ceremony."""

    if set(plan) != PLAN_FIELDS or plan["schema"] != SCHEMA:
        raise SafetyLedgerError("safety plan fields or schema differ")
    if plan["tier"] not in {"D", "S3"}:
        raise SafetyLedgerError("safety ledger tier must be D or S3")
    if plan["provenance"] not in {"PHYSICAL_MEASUREMENT", "SOFTWARE_FIXTURE"}:
        raise SafetyLedgerError("unsupported safety ledger provenance")
    for field in (
        "preflight_digest",
        "private_bundle_sha256",
        "stop_conditions_commitment_sha256",
    ):
        _require_hash(plan[field], field)
    for field in (
        "harmless_fixture_confirmed",
        "safety_protocol_approved",
        "dangerous_light_source_present",
        "scenario_approved",
    ):
        if not isinstance(plan[field], bool):
            raise SafetyLedgerError(f"{field} must be boolean")
    if not plan["harmless_fixture_confirmed"] or not plan["safety_protocol_approved"]:
        raise SafetyLedgerError("harmless fixture and safety approval are mandatory")
    if not plan["scenario_approved"]:
        raise SafetyLedgerError("unapproved hardware scenario is prohibited")
    if plan["tier"] == "S3" and plan["dangerous_light_source_present"]:
        raise SafetyLedgerError("dangerous light sources are prohibited")


def _event_body(
    *,
    sequence: int,
    kind: str,
    monotonic_ns: int,
    authorized_action_delta: int,
    unauthorized_action_delta: int,
    incident_code: str,
    previous_digest: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "kind": kind,
        "monotonic_ns": monotonic_ns,
        "authorized_action_delta": authorized_action_delta,
        "unauthorized_action_delta": unauthorized_action_delta,
        "incident_code": incident_code,
        "previous_digest": previous_digest,
    }


def append_event(
    plan: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    *,
    kind: str,
    monotonic_ns: int,
    authorized_action_delta: int = 0,
    unauthorized_action_delta: int = 0,
    incident_code: str = "NONE",
) -> dict[str, Any]:
    """Append one event after validating the complete existing chain and interlocks."""

    validate_plan(plan)
    verify_ledger(plan, events)
    if kind not in EVENT_KINDS:
        raise SafetyLedgerError("unknown safety event kind")
    if not isinstance(monotonic_ns, int) or isinstance(monotonic_ns, bool) or monotonic_ns < 0:
        raise SafetyLedgerError("monotonic_ns must be a non-negative integer")
    if authorized_action_delta not in {0, 1} or unauthorized_action_delta not in {0, 1}:
        raise SafetyLedgerError("action deltas must be zero or one")
    if not isinstance(incident_code, str) or _INCIDENT.fullmatch(incident_code) is None:
        raise SafetyLedgerError("incident_code is invalid")
    if not events and kind != "START":
        raise SafetyLedgerError("the first safety event must be START")
    if events:
        last = events[-1]
        if last["kind"] in TERMINAL_KINDS:
            raise SafetyLedgerError("terminal safety ledger cannot be extended")
        if monotonic_ns <= last["monotonic_ns"]:
            raise SafetyLedgerError("event monotonic time must increase")
        if kind == "START":
            raise SafetyLedgerError("START may occur only once")
        if kind == "ACTION" and any(
            event["kind"] in {"INCIDENT", "OPERATOR_ABORT"} for event in events
        ):
            raise SafetyLedgerError("action is blocked after incident or operator abort")
    if kind == "ACTION" and (authorized_action_delta != 1 or unauthorized_action_delta != 0):
        raise SafetyLedgerError("ACTION must record exactly one authorized action")
    if kind != "ACTION" and authorized_action_delta != 0:
        raise SafetyLedgerError("only ACTION may increment authorized actions")
    if unauthorized_action_delta and kind != "INCIDENT":
        raise SafetyLedgerError("unauthorized action must be recorded as an incident")
    if kind == "INCIDENT" and incident_code == "NONE":
        raise SafetyLedgerError("INCIDENT requires a bounded incident code")
    if kind != "INCIDENT" and incident_code != "NONE":
        raise SafetyLedgerError("incident code is permitted only on INCIDENT")

    previous = events[-1]["digest"] if events else GENESIS
    body = _event_body(
        sequence=len(events),
        kind=kind,
        monotonic_ns=monotonic_ns,
        authorized_action_delta=authorized_action_delta,
        unauthorized_action_delta=unauthorized_action_delta,
        incident_code=incident_code,
        previous_digest=previous,
    )
    plan_digest = hashlib.sha256(DOMAIN + _canonical_json(dict(plan))).digest()
    digest = hashlib.sha256(DOMAIN + plan_digest + _canonical_json(body)).hexdigest()
    return {**body, "digest": digest}


def verify_ledger(plan: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> None:
    """Recompute every link and reject truncation-unsafe or malformed sequences."""

    validate_plan(plan)
    previous = GENESIS
    previous_time = -1
    plan_digest = hashlib.sha256(DOMAIN + _canonical_json(dict(plan))).digest()
    for index, event in enumerate(events):
        if not isinstance(event, Mapping) or set(event) != EVENT_FIELDS:
            raise SafetyLedgerError(f"event {index} fields differ")
        if event["sequence"] != index or event["previous_digest"] != previous:
            raise SafetyLedgerError(f"event {index} chain position mismatch")
        if event["monotonic_ns"] <= previous_time:
            raise SafetyLedgerError(f"event {index} monotonic time is not increasing")
        body = {field: event[field] for field in EVENT_FIELDS if field != "digest"}
        expected = hashlib.sha256(DOMAIN + plan_digest + _canonical_json(body)).hexdigest()
        if not isinstance(event["digest"], str) or not hmac.compare_digest(
            expected, event["digest"]
        ):
            raise SafetyLedgerError(f"event {index} digest mismatch")
        kind = event["kind"]
        if kind not in EVENT_KINDS:
            raise SafetyLedgerError(f"event {index} has an invalid kind")
        if index == 0 and kind != "START":
            raise SafetyLedgerError("the first event must be START")
        if index > 0:
            prior = events[index - 1]
            if kind == "START":
                raise SafetyLedgerError("START may occur only once")
            if event["monotonic_ns"] <= prior["monotonic_ns"]:
                raise SafetyLedgerError("event times must be strictly increasing")
            if prior["kind"] in {"STOP", "OPERATOR_ABORT"}:
                raise SafetyLedgerError("terminal event cannot be extended")
            if kind == "ACTION" and any(
                prior_event["kind"] in {"INCIDENT", "OPERATOR_ABORT"}
                for prior_event in events[:index]
            ):
                raise SafetyLedgerError("action is blocked after incident or operator abort")
        if kind == "ACTION":
            if event["authorized_action_delta"] != 1:
                raise SafetyLedgerError("ACTION must record one authorized action")
            if event["unauthorized_action_delta"] != 0:
                raise SafetyLedgerError("ACTION cannot record an unauthorized action")
        elif event["authorized_action_delta"] != 0:
            raise SafetyLedgerError("only ACTION may increment authorized actions")
        if event["unauthorized_action_delta"] != 0 and kind != "INCIDENT":
            raise SafetyLedgerError("only INCIDENT may record an unauthorized action")
        if kind == "INCIDENT" and not event["incident_code"]:
            raise SafetyLedgerError("INCIDENT requires an incident code")
        previous = event["digest"]
        previous_time = event["monotonic_ns"]


def summarize_ledger(
    plan: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Create a bounded public summary without promoting physical verification."""

    verify_ledger(plan, events)
    if not events or events[0]["kind"] != "START" or events[-1]["kind"] not in TERMINAL_KINDS:
        raise SafetyLedgerError("public summary requires a started and terminated ledger")
    return {
        "schema": "noticer.k5.hardware_safety_summary.v1",
        "tier": plan["tier"],
        "hardware_status": "NOT_VERIFIED",
        "provenance": plan["provenance"],
        "preflight_digest": plan["preflight_digest"],
        "private_bundle_sha256": plan["private_bundle_sha256"],
        "event_count": len(events),
        "authorized_action_count": sum(event["authorized_action_delta"] for event in events),
        "unauthorized_action_count": sum(
            event["unauthorized_action_delta"] for event in events
        ),
        "incident_count": sum(event["kind"] == "INCIDENT" for event in events),
        "operator_aborted": events[-1]["kind"] == "OPERATOR_ABORT",
        "ledger_head": events[-1]["digest"],
    }
