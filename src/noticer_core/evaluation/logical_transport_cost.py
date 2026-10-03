"""Platform-independent runtime-event to QuotientForge cost contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

FORMAT_VERSION = "noticer.k7.logical-transport-cost.v1"
EVENT_KINDS = ("delivery", "frame", "radio_on", "reconnect", "retry", "state_count")
MEAN_LATENCY_SCALE = 1_000_000
U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1


class LogicalCostError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class RuntimeEvent:
    kind: str
    slot: int
    byte_count: int = 0
    ready_slot: int | None = None
    dummy: bool = False
    state_count: int = 0


@dataclass(frozen=True)
class LogicalCostVector:
    bytes: int
    dummy_frames: int
    total_frames: int
    worst_latency: int
    mean_latency_scaled: int
    state_count: int
    reconnects: int
    retries: int
    radio_on_slots: int


@dataclass(frozen=True)
class LogicalCostArtifact:
    format_version: str
    event_trace_sha256: str
    mean_latency_scale: int
    units: tuple[str, ...]
    cost: LogicalCostVector


def compute_logical_cost(events: tuple[RuntimeEvent, ...]) -> LogicalCostArtifact:
    """Validate a canonical public event trace and compute its logical cost."""

    if not events:
        raise LogicalCostError("empty_trace")
    previous_slot = -1
    bytes_total = dummy_frames = total_frames = reconnects = retries = 0
    latencies: list[int] = []
    radio_slots: set[int] = set()
    declared_states: list[int] = []
    for event in events:
        _validate_event(event)
        if event.slot < previous_slot:
            raise LogicalCostError("noncanonical_event_order")
        previous_slot = event.slot
        if event.kind == "frame":
            total_frames = _add_u64(total_frames, 1)
            bytes_total = _add_u64(bytes_total, event.byte_count)
            dummy_frames = _add_u64(dummy_frames, int(event.dummy))
        elif event.kind == "delivery":
            assert event.ready_slot is not None
            latencies.append(event.slot - event.ready_slot)
        elif event.kind == "retry":
            retries = _add_u32(retries, 1)
        elif event.kind == "reconnect":
            reconnects = _add_u32(reconnects, 1)
        elif event.kind == "radio_on":
            if event.slot in radio_slots:
                raise LogicalCostError("duplicate_radio_slot")
            radio_slots.add(event.slot)
        else:
            declared_states.append(event.state_count)
    if len(declared_states) != 1:
        raise LogicalCostError("state_count_cardinality")
    worst = max(latencies, default=0)
    mean = (
        0
        if not latencies
        else _checked_u64(sum(latencies) * MEAN_LATENCY_SCALE // len(latencies))
    )
    cost = LogicalCostVector(
        bytes_total, dummy_frames, total_frames, worst, mean,
        declared_states[0], reconnects, retries, len(radio_slots),
    )
    trace_json = json.dumps(
        [asdict(event) for event in events], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return LogicalCostArtifact(
        FORMAT_VERSION,
        hashlib.sha256(trace_json).hexdigest(),
        MEAN_LATENCY_SCALE,
        ("bytes", "frames", "slots", "states", "count"),
        cost,
    )


def canonical_artifact_json(artifact: LogicalCostArtifact) -> str:
    if (
        artifact.format_version != FORMAT_VERSION
        or artifact.mean_latency_scale != MEAN_LATENCY_SCALE
    ):
        raise LogicalCostError("invalid_artifact_header")
    return json.dumps(asdict(artifact), sort_keys=True, separators=(",", ":"))


def artifact_digest(artifact: LogicalCostArtifact) -> str:
    return hashlib.sha256(canonical_artifact_json(artifact).encode("utf-8")).hexdigest()


def _validate_event(event: RuntimeEvent) -> None:
    if (
        event.kind not in EVENT_KINDS
        or type(event.slot) is not int
        or not 0 <= event.slot <= U64_MAX
    ):
        raise LogicalCostError("invalid_event")
    if (
        type(event.byte_count) is not int
        or type(event.state_count) is not int
        or type(event.dummy) is not bool
    ):
        raise LogicalCostError("invalid_event")
    if event.kind == "frame":
        if (
            not 0 <= event.byte_count <= U64_MAX
            or event.ready_slot is not None
            or event.state_count
        ):
            raise LogicalCostError("invalid_frame_event")
    elif event.kind == "delivery":
        if (
            type(event.ready_slot) is not int
            or event.ready_slot < 0
            or event.ready_slot > event.slot
            or event.byte_count
            or event.dummy
            or event.state_count
        ):
            raise LogicalCostError("invalid_delivery_event")
    elif event.kind == "state_count":
        if (
            not 0 <= event.state_count <= U32_MAX
            or event.byte_count
            or event.ready_slot is not None
            or event.dummy
        ):
            raise LogicalCostError("invalid_state_event")
    elif event.byte_count or event.ready_slot is not None or event.dummy or event.state_count:
        raise LogicalCostError("unexpected_event_field")


def _checked_u64(value: int) -> int:
    if value > U64_MAX:
        raise LogicalCostError("u64_overflow")
    return value


def _add_u64(left: int, right: int) -> int:
    return _checked_u64(left + right)


def _add_u32(left: int, right: int) -> int:
    value = left + right
    if value > U32_MAX:
        raise LogicalCostError("u32_overflow")
    return value
