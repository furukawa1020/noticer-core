"""Size-padding reference that preserves release time and frame count."""

from bisect import bisect_left
from collections.abc import Iterable

from noticer_core.evaluation.k20_release_reference import (
    ObservedFrame,
    ReleaseRequest,
    ReleaseSimulation,
    release_inputs,
)


def simulate_padding_only(
    requests: Iterable[ReleaseRequest],
    *,
    horizon: int,
    crypto_bytes: int,
    buckets: tuple[int, ...],
) -> ReleaseSimulation:
    """Use the smallest declared wire-length bucket, with no cover or time shift."""
    ordered = release_inputs(requests, horizon=horizon, crypto_bytes=crypto_bytes)
    if not buckets or any(type(bucket) is not int or bucket <= crypto_bytes for bucket in buckets):
        raise ValueError("padding buckets must fit a nonempty body")
    if tuple(sorted(set(buckets))) != buckets:
        raise ValueError("padding buckets must be strictly increasing")
    frames: list[ObservedFrame] = []
    for item in ordered:
        index = bisect_left(buckets, item.body_bytes + crypto_bytes)
        if index == len(buckets):
            raise ValueError("no configured bucket fits the request")
        frames.append(ObservedFrame(item.ready_slot, buckets[index]))
    return ReleaseSimulation(
        tuple(frames), tuple((item.action_id, item.ready_slot) for item in ordered), ()
    )
