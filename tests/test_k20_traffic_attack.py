from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_traffic import (
    LabelledTrafficTrace,
    TrafficAttackError,
    TrafficSessionTrace,
    run_traffic_analysis_attack,
)


def trace(session: str, *, interval: float, size: float) -> TrafficSessionTrace:
    return TrafficSessionTrace(
        session,
        np.arange(8, dtype=float) * interval,
        np.full(8, size),
        np.asarray([True, False] * 4),
        np.zeros(8, dtype=bool),
    )


def labelled(prefix: str) -> tuple[LabelledTrafficTrace, ...]:
    return tuple(
        [
            LabelledTrafficTrace(trace(f"{prefix}_a_{index}", interval=1.0, size=64), "person_a001")
            for index in range(3)
        ]
        + [
            LabelledTrafficTrace(
                trace(f"{prefix}_b_{index}", interval=4.0, size=256),
                "person_b001",
            )
            for index in range(3)
        ]
    )


def test_payload_blind_traffic_attack_detects_deliberate_cadence_leak() -> None:
    test = (
        trace("test_a", interval=1.0, size=64),
        trace("test_b", interval=4.0, size=256),
    )
    result = run_traffic_analysis_attack(
        labelled("train"),
        labelled("valid"),
        test,
        regularization_candidates=(0.1, 1.0, 10.0),
        seed=5,
    )
    assert result.predicted_labels.tolist() == ["person_a001", "person_b001"]
    assert result.attacker_id == "k20-traffic-logistic-v1"


def test_traffic_attack_is_reproducible() -> None:
    test = (
        trace("test_a", interval=1.0, size=64),
        trace("test_b", interval=4.0, size=256),
    )
    outputs = [
        run_traffic_analysis_attack(
            labelled("train"), labelled("valid"), test, regularization_candidates=(1.0,), seed=5
        ).probabilities
        for _ in range(2)
    ]
    np.testing.assert_array_equal(outputs[0], outputs[1])


def test_non_monotonic_timestamps_are_rejected() -> None:
    broken = trace("broken", interval=1.0, size=64)
    object.__setattr__(broken, "timestamps", np.asarray([0.0, 2.0, 1.0, 3.0]))
    object.__setattr__(broken, "wire_sizes", np.full(4, 64.0))
    object.__setattr__(broken, "outbound", np.ones(4, dtype=bool))
    object.__setattr__(broken, "retries", np.zeros(4, dtype=bool))
    with pytest.raises(TrafficAttackError, match="increase"):
        broken.features()


def test_empty_test_partition_is_rejected() -> None:
    with pytest.raises(TrafficAttackError, match="must not be empty"):
        run_traffic_analysis_attack(
            labelled("train"),
            labelled("valid"),
            (),
            regularization_candidates=(1.0,),
            seed=5,
        )
