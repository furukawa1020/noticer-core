from dataclasses import replace

import pytest

from noticer_core.evaluation.logical_transport_cost import (
    LogicalCostError,
    RuntimeEvent,
    artifact_digest,
    canonical_artifact_json,
    compute_logical_cost,
)


def _events() -> tuple[RuntimeEvent, ...]:
    return (
        RuntimeEvent("state_count", 0, state_count=3),
        RuntimeEvent("radio_on", 0),
        RuntimeEvent("frame", 0, byte_count=64, dummy=True),
        RuntimeEvent("retry", 1),
        RuntimeEvent("reconnect", 2),
        RuntimeEvent("radio_on", 2),
        RuntimeEvent("frame", 2, byte_count=32),
        RuntimeEvent("delivery", 3, ready_slot=1),
        RuntimeEvent("delivery", 4, ready_slot=0),
    )


def test_logical_cost_is_exact_and_byte_reproducible() -> None:
    first = compute_logical_cost(_events())
    second = compute_logical_cost(_events())
    assert first == second
    assert first.cost.bytes == 96
    assert first.cost.dummy_frames == 1
    assert first.cost.total_frames == 2
    assert first.cost.worst_latency == 4
    assert first.cost.mean_latency_scaled == 3_000_000
    assert first.cost.state_count == 3
    assert first.cost.reconnects == first.cost.retries == 1
    assert first.cost.radio_on_slots == 2
    assert canonical_artifact_json(first) == canonical_artifact_json(second)
    assert artifact_digest(first) == artifact_digest(second)
    assert "security" not in canonical_artifact_json(first)
    assert "utility" not in canonical_artifact_json(first)


@pytest.mark.parametrize(
    "events,category",
    [
        ((), "empty_trace"),
        ((_events()[0], RuntimeEvent("unknown", 1)), "invalid_event"),
        (
            (_events()[0], RuntimeEvent("retry", 2), RuntimeEvent("retry", 1)),
            "noncanonical_event_order",
        ),
        (
            (_events()[0], RuntimeEvent("radio_on", 1), RuntimeEvent("radio_on", 1)),
            "duplicate_radio_slot",
        ),
        ((RuntimeEvent("frame", 0, byte_count=1),), "state_count_cardinality"),
        ((_events()[0], replace(_events()[1], byte_count=1)), "unexpected_event_field"),
    ],
)
def test_invalid_or_ambiguous_event_traces_fail_closed(events, category) -> None:
    with pytest.raises(LogicalCostError) as caught:
        compute_logical_cost(events)
    assert caught.value.category == category
