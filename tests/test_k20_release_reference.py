import pytest

from noticer_core.evaluation.k20_release_reference import (
    ObservedFrame,
    ReleaseRequest,
    simulate_encryption_only,
)


def test_encryption_only_retains_timing_and_variable_lengths() -> None:
    requests = [ReleaseRequest("b", 4, 4, 7), ReleaseRequest("a", 0, 5, 3)]
    run = simulate_encryption_only(requests, horizon=5, crypto_bytes=16)
    assert run.frames == (ObservedFrame(0, 19), ObservedFrame(4, 23))
    assert run.deliveries == (("a", 0), ("b", 4))
    assert not run.undelivered


def test_out_of_horizon_request_is_invalid() -> None:
    with pytest.raises(ValueError, match="release slot"):
        simulate_encryption_only([ReleaseRequest("a", 3, 3, 2)], horizon=3, crypto_bytes=1)
