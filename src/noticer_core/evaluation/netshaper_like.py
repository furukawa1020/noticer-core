"""Windowed-noise comparison approximation without a DP guarantee."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass

import numpy as np

from noticer_core.evaluation.baseline_comparison_contract import (
    ComparisonManifest,
    manifest_digest,
    validate_manifest,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    PrivateDelivery,
    PublicFrame,
    fault_trace_digest,
    utility_trace_digest,
)


class NetShaperLikeError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class NetShaperLikeConfig:
    horizon_slots: int
    window_slots: int
    frame_bytes: int
    max_frames_per_window: int
    noise_scale_frames: float
    seed: int


@dataclass(frozen=True)
class NetShaperLikeRun:
    format_version: str
    comparison_manifest_sha256: str
    config_sha256: str
    public_trace: tuple[PublicFrame, ...]
    private_deliveries: tuple[PrivateDelivery, ...]
    bandwidth_bytes: int
    max_pending_actions: int
    public_fault_slots: int
    missed_deadlines: int
    privacy_notion: str = "windowed-noise-approximation-no-dp-proof"
    implementation_kind: str = "approximation"
    security_proof: bool = False


def run_netshaper_like(
    manifest: ComparisonManifest,
    config: NetShaperLikeConfig,
    actions: tuple[ActionObligation, ...],
    network_available: tuple[bool, ...],
) -> NetShaperLikeRun:
    """Simulate noisy window counts over a shared finite fault/utility trace."""

    validate_manifest(manifest)
    mechanism = next(
        item for item in manifest.mechanisms if item.mechanism_id == "netshaper_like"
    )
    if mechanism.implementation_kind != "approximation":
        raise NetShaperLikeError("not_approximation")
    if (
        config.horizon_slots <= 0
        or config.window_slots <= 0
        or config.frame_bytes <= 0
        or config.max_frames_per_window <= 0
        or config.max_frames_per_window > config.window_slots
        or not math.isfinite(config.noise_scale_frames)
        or config.noise_scale_frames <= 0
        or config.seed < 0
    ):
        raise NetShaperLikeError("invalid_config")
    if len(network_available) != config.horizon_slots or any(
        type(value) is not bool for value in network_available
    ):
        raise NetShaperLikeError("invalid_fault_trace")
    if len({action.action_id for action in actions}) != len(actions):
        raise NetShaperLikeError("duplicate_action")
    if any(
        not action.action_id
        or action.ready_slot < 0
        or action.ready_slot >= config.horizon_slots
        or action.deadline_slot < action.ready_slot
        or action.deadline_slot >= config.horizon_slots
        for action in actions
    ):
        raise NetShaperLikeError("invalid_action")
    if config_digest(config) != mechanism.selected_config_sha256:
        raise NetShaperLikeError("config_binding_mismatch")
    if fault_trace_digest(network_available) != manifest.shared.fault_trace_sha256:
        raise NetShaperLikeError("fault_binding_mismatch")
    if utility_trace_digest(actions) != manifest.shared.utility_sha256:
        raise NetShaperLikeError("utility_binding_mismatch")

    rng = np.random.default_rng(config.seed)
    ordered = sorted(actions, key=lambda action: (action.ready_slot, action.action_id))
    pending: list[ActionObligation] = []
    delivered: dict[str, int] = {}
    frames: list[PublicFrame] = []
    cursor = 0
    max_pending = 0
    for start in range(0, config.horizon_slots, config.window_slots):
        end = min(config.horizon_slots, start + config.window_slots)
        while cursor < len(ordered) and ordered[cursor].ready_slot <= start:
            pending.append(ordered[cursor])
            cursor += 1
        max_pending = max(max_pending, len(pending))
        noisy_count = len(pending) + float(rng.laplace(0.0, config.noise_scale_frames))
        target = min(config.max_frames_per_window, max(0, round(noisy_count)))
        sent = 0
        for slot in range(start, end):
            while cursor < len(ordered) and ordered[cursor].ready_slot <= slot:
                pending.append(ordered[cursor])
                cursor += 1
            max_pending = max(max_pending, len(pending))
            available = network_available[slot]
            transmitted = available and sent < target
            frames.append(
                PublicFrame(slot, config.frame_bytes, available, transmitted)
            )
            if transmitted:
                sent += 1
                if pending:
                    selected = min(
                        pending,
                        key=lambda action: (action.deadline_slot, action.action_id),
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
    return NetShaperLikeRun(
        format_version="noticer.k7.netshaper-like-run.v1",
        comparison_manifest_sha256=manifest_digest(manifest),
        config_sha256=config_digest(config),
        public_trace=tuple(frames),
        private_deliveries=private_deliveries,
        bandwidth_bytes=sum(
            frame.frame_bytes for frame in frames if frame.transmitted
        ),
        max_pending_actions=max_pending,
        public_fault_slots=sum(not available for available in network_available),
        missed_deadlines=sum(
            not delivery.deadline_met for delivery in private_deliveries
        ),
    )


def config_digest(config: NetShaperLikeConfig) -> str:
    data = json.dumps(
        asdict(config), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
