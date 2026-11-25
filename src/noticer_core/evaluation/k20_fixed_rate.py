"""Fixed-rate, fixed-length FIFO reference with observable cover traffic."""

from collections.abc import Iterable

from noticer_core.evaluation.k20_release_reference import (
    ObservedFrame,
    ReleaseRequest,
    ReleaseSimulation,
    release_inputs,
)


def simulate_fixed_rate(
    requests: Iterable[ReleaseRequest],
    *,
    horizon: int,
    period: int,
    frame_bytes: int,
    crypto_bytes: int,
) -> ReleaseSimulation:
    """Emit one frame each public period; report late and undelivered separately via slots."""
    ordered = release_inputs(requests, horizon=horizon, crypto_bytes=crypto_bytes)
    if type(period) is not int or period < 1:
        raise ValueError("period must be a positive integer")
    if type(frame_bytes) is not int or frame_bytes <= crypto_bytes:
        raise ValueError("frame_bytes must fit a nonempty body")
    if any(item.body_bytes + crypto_bytes > frame_bytes for item in ordered):
        raise ValueError("frame_bytes is too small for a request")
    frames: list[ObservedFrame] = []
    delivered: list[tuple[str, int]] = []
    cursor = 0
    for slot in range(0, horizon, period):
        frames.append(ObservedFrame(slot, frame_bytes))
        if cursor < len(ordered) and ordered[cursor].ready_slot <= slot:
            delivered.append((ordered[cursor].action_id, slot))
            cursor += 1
    return ReleaseSimulation(
        tuple(frames), tuple(delivered), tuple(item.action_id for item in ordered[cursor:])
    )
