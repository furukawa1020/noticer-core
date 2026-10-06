from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from noticer_core.evaluation.hardware_safety_ledger import (
    SafetyLedgerError,
    append_event,
    summarize_ledger,
    verify_ledger,
)


def _plan(tier: str = "D", provenance: str = "PHYSICAL_MEASUREMENT") -> dict[str, Any]:
    return {
        "schema": "noticer.k5.hardware_safety_ledger.v1",
        "tier": tier,
        "provenance": provenance,
        "preflight_digest": "a" * 64,
        "private_bundle_sha256": "b" * 64,
        "harmless_fixture_confirmed": True,
        "safety_protocol_approved": True,
        "stop_conditions_commitment_sha256": "c" * 64,
        "dangerous_light_source_present": False,
        "scenario_approved": True,
    }


def _append(
    plan: dict[str, Any],
    events: list[dict[str, Any]],
    kind: str,
    time: int,
    **kwargs: Any,
) -> None:
    events.append(append_event(plan, events, kind=kind, monotonic_ns=time, **kwargs))


def test_exactly_one_safe_action_and_stop_produce_bounded_summary() -> None:
    plan = _plan()
    events: list[dict[str, Any]] = []
    _append(plan, events, "START", 1)
    _append(plan, events, "ACTION", 2, authorized_action_delta=1)
    _append(plan, events, "STOP", 3)

    summary = summarize_ledger(plan, events)
    assert summary["hardware_status"] == "NOT_VERIFIED"
    assert summary["authorized_action_count"] == 1
    assert summary["unauthorized_action_count"] == 0
    assert len(summary["ledger_head"]) == 64


def test_incident_blocks_later_action_and_records_unauthorized_action() -> None:
    plan = _plan()
    events: list[dict[str, Any]] = []
    _append(plan, events, "START", 1)
    _append(
        plan,
        events,
        "INCIDENT",
        2,
        unauthorized_action_delta=1,
        incident_code="UNEXPECTED_ACTION",
    )
    with pytest.raises(SafetyLedgerError, match="blocked after incident"):
        append_event(plan, events, kind="ACTION", monotonic_ns=3, authorized_action_delta=1)
    _append(plan, events, "OPERATOR_ABORT", 3)
    summary = summarize_ledger(plan, events)
    assert summary["operator_aborted"] is True
    assert summary["incident_count"] == 1


def test_tamper_terminal_extension_and_dangerous_s3_fail_closed() -> None:
    plan = _plan()
    events: list[dict[str, Any]] = []
    _append(plan, events, "START", 1)
    _append(plan, events, "STOP", 2)
    altered = deepcopy(events)
    altered[0]["kind"] = "ACTION"
    with pytest.raises(SafetyLedgerError, match="digest mismatch"):
        verify_ledger(plan, altered)
    with pytest.raises(SafetyLedgerError, match="terminal"):
        append_event(plan, events, kind="REJECTION", monotonic_ns=3)

    dangerous = _plan("S3")
    dangerous["dangerous_light_source_present"] = True
    with pytest.raises(SafetyLedgerError, match="dangerous light"):
        append_event(dangerous, [], kind="START", monotonic_ns=1)


def test_software_fixture_summary_never_promotes_hardware() -> None:
    plan = _plan(provenance="SOFTWARE_FIXTURE")
    events: list[dict[str, Any]] = []
    _append(plan, events, "START", 1)
    _append(plan, events, "STOP", 2)
    assert summarize_ledger(plan, events)["hardware_status"] == "NOT_VERIFIED"
