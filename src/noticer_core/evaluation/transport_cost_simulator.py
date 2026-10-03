"""Deterministic public transport simulator for K7 cost calibration."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, dataclass

from noticer_core.evaluation.logical_transport_cost import (
    LogicalCostArtifact,
    RuntimeEvent,
    compute_logical_cost,
)
from noticer_core.evaluation.transport_cost_profile import PlatformProfile, profile_digest

FORMAT_VERSION = "noticer.k7.transport-cost-simulation.v1"


class TransportSimulationError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class TransportSimulationConfig:
    format_version: str
    simulator_version: str
    seed: int
    frame_overhead_bytes: int
    state_count: int
    cover_modulus: int
    max_events: int


@dataclass(frozen=True)
class PublicRequest:
    request_id: str
    ready_slot: int
    deadline_slot: int
    payload_bytes: int


@dataclass(frozen=True)
class TransportSimulationArtifact:
    format_version: str
    simulator_version: str
    seed: int
    config_sha256: str
    input_sha256: str
    platform_profile_sha256: str
    events: tuple[RuntimeEvent, ...]
    logical_cost: LogicalCostArtifact
    status: str = "COMPLETE"


def simulate_transport_cost(
    config: TransportSimulationConfig,
    requests: tuple[PublicRequest, ...],
    network_available: tuple[bool, ...],
    profile: PlatformProfile,
) -> TransportSimulationArtifact:
    """Run a bounded simulation or fail without emitting a success artifact."""

    _validate_inputs(config, requests, network_available)
    rng = random.Random(config.seed)
    events = [RuntimeEvent("state_count", 0, state_count=config.state_count)]
    pending: list[PublicRequest] = []
    delivered: set[str] = set()
    previous_available = network_available[0]
    for slot, available in enumerate(network_available):
        pending.extend(request for request in requests if request.ready_slot == slot)
        if available and not previous_available:
            events.append(RuntimeEvent("reconnect", slot))
        previous_available = available
        if pending:
            events.append(RuntimeEvent("radio_on", slot))
            if available:
                request = pending.pop(0)
                events.append(
                    RuntimeEvent(
                        "frame",
                        slot,
                        byte_count=request.payload_bytes + config.frame_overhead_bytes,
                    )
                )
                events.append(RuntimeEvent("delivery", slot, ready_slot=request.ready_slot))
                delivered.add(request.request_id)
            else:
                events.append(RuntimeEvent("retry", slot))
        elif available and rng.randrange(config.cover_modulus) == 0:
            events.extend(
                (
                    RuntimeEvent("radio_on", slot),
                    RuntimeEvent(
                        "frame",
                        slot,
                        byte_count=config.frame_overhead_bytes,
                        dummy=True,
                    ),
                )
            )
        if len(events) > config.max_events:
            raise TransportSimulationError("event_limit_exceeded")
    if pending or delivered != {request.request_id for request in requests}:
        raise TransportSimulationError("undelivered_request")
    logical = compute_logical_cost(tuple(events))
    input_document = {
        "network_available": network_available,
        "requests": [asdict(request) for request in requests],
    }
    return TransportSimulationArtifact(
        FORMAT_VERSION,
        config.simulator_version,
        config.seed,
        _digest(asdict(config)),
        _digest(input_document),
        profile_digest(profile),
        tuple(events),
        logical,
    )


def canonical_simulation_json(artifact: TransportSimulationArtifact) -> str:
    if artifact.format_version != FORMAT_VERSION or artifact.status != "COMPLETE":
        raise TransportSimulationError("invalid_artifact_status")
    return json.dumps(asdict(artifact), sort_keys=True, separators=(",", ":"))


def _validate_inputs(config, requests, availability) -> None:
    if (
        config.format_version != FORMAT_VERSION
        or not config.simulator_version
        or type(config.seed) is not int
        or config.frame_overhead_bytes < 1
        or config.state_count < 1
        or config.cover_modulus < 1
        or config.max_events < 1
        or not availability
        or any(type(value) is not bool for value in availability)
    ):
        raise TransportSimulationError("invalid_config")
    ids = tuple(request.request_id for request in requests)
    if ids != tuple(sorted(set(ids))):
        raise TransportSimulationError("noncanonical_requests")
    horizon = len(availability)
    if any(
        not request.request_id
        or type(request.ready_slot) is not int
        or type(request.deadline_slot) is not int
        or type(request.payload_bytes) is not int
        or not 0 <= request.ready_slot <= request.deadline_slot < horizon
        or request.payload_bytes < 0
        for request in requests
    ):
        raise TransportSimulationError("invalid_request")


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
