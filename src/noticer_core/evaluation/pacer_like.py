"""Fixed-cadence approximation baseline, not the original Pacer system."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from noticer_core.evaluation.baseline_comparison_contract import (
    ComparisonManifest,
    manifest_digest,
    validate_manifest,
)


class PacerLikeError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class PacerLikeConfig:
    horizon_slots: int
    period_slots: int
    frame_bytes: int


@dataclass(frozen=True)
class ActionObligation:
    action_id: str
    ready_slot: int
    deadline_slot: int


@dataclass(frozen=True)
class PublicFrame:
    slot: int
    frame_bytes: int
    network_available: bool
    transmitted: bool


@dataclass(frozen=True)
class PrivateDelivery:
    action_id: str
    delivered_slot: int | None
    latency_slots: int | None
    deadline_met: bool


@dataclass(frozen=True)
class PacerLikeRun:
    format_version: str
    comparison_manifest_sha256: str
    config_sha256: str
    public_trace: tuple[PublicFrame, ...]
    private_deliveries: tuple[PrivateDelivery, ...]
    bandwidth_bytes: int
    max_pending_actions: int
    public_fault_slots: int
    missed_deadlines: int
    implementation_kind: str = "approximation"
    security_proof: bool = False


def run_pacer_like(
    manifest: ComparisonManifest,
    config: PacerLikeConfig,
    actions: tuple[ActionObligation, ...],
    network_available: tuple[bool, ...],
) -> PacerLikeRun:
    """Run one shared-contract fixed schedule with public fault pauses."""

    validate_manifest(manifest)
    mechanism = next(
        item for item in manifest.mechanisms if item.mechanism_id == "pacer_like"
    )
    if mechanism.implementation_kind != "approximation":
        raise PacerLikeError("not_approximation")
    if config.horizon_slots <= 0 or config.period_slots <= 0 or config.frame_bytes <= 0:
        raise PacerLikeError("invalid_config")
    if len(network_available) != config.horizon_slots or any(
        type(value) is not bool for value in network_available
    ):
        raise PacerLikeError("invalid_fault_trace")
    if len({action.action_id for action in actions}) != len(actions):
        raise PacerLikeError("duplicate_action")
    if any(
        not action.action_id
        or action.ready_slot < 0
        or action.ready_slot >= config.horizon_slots
        or action.deadline_slot < action.ready_slot
        or action.deadline_slot >= config.horizon_slots
        for action in actions
    ):
        raise PacerLikeError("invalid_action")
    if config_digest(config) != mechanism.selected_config_sha256:
        raise PacerLikeError("config_binding_mismatch")
    if fault_trace_digest(network_available) != manifest.shared.fault_trace_sha256:
        raise PacerLikeError("fault_binding_mismatch")
    if utility_trace_digest(actions) != manifest.shared.utility_sha256:
        raise PacerLikeError("utility_binding_mismatch")

    pending: list[ActionObligation] = []
    delivered: dict[str, int] = {}
    public_frames: list[PublicFrame] = []
    max_pending = 0
    ordered = sorted(actions, key=lambda action: (action.ready_slot, action.action_id))
    cursor = 0
    for slot in range(config.horizon_slots):
        while cursor < len(ordered) and ordered[cursor].ready_slot <= slot:
            pending.append(ordered[cursor])
            cursor += 1
        max_pending = max(max_pending, len(pending))
        if slot % config.period_slots != 0:
            continue
        available = network_available[slot]
        public_frames.append(PublicFrame(slot, config.frame_bytes, available, available))
        if available and pending:
            selected = min(
                pending, key=lambda action: (action.deadline_slot, action.action_id)
            )
            pending.remove(selected)
            delivered[selected.action_id] = slot

    private_deliveries = tuple(
        PrivateDelivery(
            action_id=action.action_id,
            delivered_slot=delivered.get(action.action_id),
            latency_slots=(
                delivered[action.action_id] - action.ready_slot
                if action.action_id in delivered else None
            ),
            deadline_met=(
                action.action_id in delivered
                and delivered[action.action_id] <= action.deadline_slot
            ),
        )
        for action in sorted(actions, key=lambda action: action.action_id)
    )
    return PacerLikeRun(
        format_version="noticer.k7.pacer-like-run.v1",
        comparison_manifest_sha256=manifest_digest(manifest),
        config_sha256=config_digest(config),
        public_trace=tuple(public_frames),
        private_deliveries=private_deliveries,
        bandwidth_bytes=sum(
            frame.frame_bytes for frame in public_frames if frame.transmitted
        ),
        max_pending_actions=max_pending,
        public_fault_slots=sum(not available for available in network_available),
        missed_deadlines=sum(
            not delivery.deadline_met for delivery in private_deliveries
        ),
    )


def config_digest(config: PacerLikeConfig) -> str:
    return _digest(asdict(config))


def fault_trace_digest(network_available: tuple[bool, ...]) -> str:
    return _digest({"network_available": network_available})


def utility_trace_digest(actions: tuple[ActionObligation, ...]) -> str:
    return _digest({
        "actions": [asdict(action) for action in sorted(
            actions, key=lambda action: action.action_id
        )]
    })


def _digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
