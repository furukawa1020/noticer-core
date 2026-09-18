"""Matched-action handwritten shaper and deliberately leaky controls."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Literal

from noticer_core.evaluation.baseline_comparison_contract import (
    ComparisonManifest,
    manifest_digest,
    validate_manifest,
)
from noticer_core.evaluation.pacer_like import fault_trace_digest


class HandwrittenControlError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class HandwrittenConfig:
    horizon_slots: int
    frame_bytes: int
    leaky_increment_bytes: int


@dataclass(frozen=True)
class MatchedAction:
    action_id: str
    service_id: str
    deadline_slot: int
    private_ready_slot: int
    private_bit: Literal[0, 1]


@dataclass(frozen=True)
class ObserverFrame:
    slot: int
    frame_bytes: int
    service_id: str


@dataclass(frozen=True)
class MechanismTrace:
    mechanism_id: str
    observer_frames: tuple[ObserverFrame, ...]
    delivered_slot: int | None
    deadline_met: bool
    bandwidth_bytes: int
    public_fault_slots: int


@dataclass(frozen=True)
class ControlComparison:
    format_version: str
    comparison_manifest_sha256: str
    config_sha256: str
    status: str
    aets_trace_equal: bool
    immediate_control_detected: bool
    leaky_control_detected: bool
    left: tuple[MechanismTrace, ...]
    right: tuple[MechanismTrace, ...]
    security_proof: bool = False


def compare_matched_actions(
    manifest: ComparisonManifest,
    config: HandwrittenConfig,
    left: MatchedAction,
    right: MatchedAction,
    network_available: tuple[bool, ...],
) -> ControlComparison:
    """Evaluate three mechanisms on one fixed public action/fault fixture."""

    validate_manifest(manifest)
    _validate(config, left, right, network_available)
    if (
        left.action_id != right.action_id
        or left.service_id != right.service_id
        or left.deadline_slot != right.deadline_slot
    ):
        raise HandwrittenControlError("not_matched_action")
    for mechanism_id in ("handwritten_aets", "immediate_control", "leaky_control"):
        mechanism = next(
            item for item in manifest.mechanisms
            if item.mechanism_id == mechanism_id
        )
        if mechanism.implementation_kind != "local":
            raise HandwrittenControlError("not_local_implementation")
        if mechanism.selected_config_sha256 != config_digest(config):
            raise HandwrittenControlError("config_binding_mismatch")
    if fault_trace_digest(network_available) != manifest.shared.fault_trace_sha256:
        raise HandwrittenControlError("fault_binding_mismatch")
    if action_semantics_digest(left) != manifest.shared.utility_sha256:
        raise HandwrittenControlError("utility_binding_mismatch")

    left_traces = tuple(
        _run(mechanism_id, config, left, network_available)
        for mechanism_id in ("handwritten_aets", "immediate_control", "leaky_control")
    )
    right_traces = tuple(
        _run(mechanism_id, config, right, network_available)
        for mechanism_id in ("handwritten_aets", "immediate_control", "leaky_control")
    )
    aets_equal = left_traces[0].observer_frames == right_traces[0].observer_frames
    immediate_detected = (
        left_traces[1].observer_frames != right_traces[1].observer_frames
    )
    leaky_detected = left_traces[2].observer_frames != right_traces[2].observer_frames
    return ControlComparison(
        format_version="noticer.k7.handwritten-controls.v1",
        comparison_manifest_sha256=manifest_digest(manifest),
        config_sha256=config_digest(config),
        status=(
            "VALID" if aets_equal and immediate_detected and leaky_detected
            else "INVALID_EVALUATION"
        ),
        aets_trace_equal=aets_equal,
        immediate_control_detected=immediate_detected,
        leaky_control_detected=leaky_detected,
        left=left_traces,
        right=right_traces,
    )


def action_semantics_digest(action: MatchedAction) -> str:
    return _digest({
        "action_id": action.action_id,
        "service_id": action.service_id,
        "deadline_slot": action.deadline_slot,
    })


def config_digest(config: HandwrittenConfig) -> str:
    return _digest(asdict(config))


def _run(
    mechanism_id: str,
    config: HandwrittenConfig,
    action: MatchedAction,
    availability: tuple[bool, ...],
) -> MechanismTrace:
    first_slot = (
        action.private_ready_slot if mechanism_id == "immediate_control"
        else action.deadline_slot
    )
    delivered_slot = next(
        (slot for slot in range(first_slot, config.horizon_slots) if availability[slot]),
        None,
    )
    frame_bytes = config.frame_bytes + (
        config.leaky_increment_bytes * action.private_bit
        if mechanism_id == "leaky_control" else 0
    )
    frames = (
        (ObserverFrame(delivered_slot, frame_bytes, action.service_id),)
        if delivered_slot is not None else ()
    )
    return MechanismTrace(
        mechanism_id=mechanism_id,
        observer_frames=frames,
        delivered_slot=delivered_slot,
        deadline_met=(
            delivered_slot is not None and delivered_slot <= action.deadline_slot
        ),
        bandwidth_bytes=sum(frame.frame_bytes for frame in frames),
        public_fault_slots=sum(not value for value in availability),
    )


def _validate(
    config: HandwrittenConfig,
    left: MatchedAction,
    right: MatchedAction,
    availability: tuple[bool, ...],
) -> None:
    if (
        config.horizon_slots <= 0
        or config.frame_bytes <= 0
        or config.leaky_increment_bytes <= 0
        or len(availability) != config.horizon_slots
        or any(type(value) is not bool for value in availability)
    ):
        raise HandwrittenControlError("invalid_config_or_fault")
    for action in (left, right):
        if (
            not action.action_id
            or not action.service_id
            or action.deadline_slot < 0
            or action.deadline_slot >= config.horizon_slots
            or action.private_ready_slot < 0
            or action.private_ready_slot > action.deadline_slot
            or type(action.private_bit) is not int
            or action.private_bit not in (0, 1)
        ):
            raise HandwrittenControlError("invalid_action")


def _digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
