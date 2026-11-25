import pytest

from noticer_core.evaluation.k20_padding_only import simulate_padding_only
from noticer_core.evaluation.k20_release_reference import ObservedFrame, ReleaseRequest


def test_padding_changes_size_but_not_release_timing() -> None:
    run = simulate_padding_only(
        [ReleaseRequest("a", 1, 2, 3), ReleaseRequest("b", 4, 4, 12)],
        horizon=5, crypto_bytes=4, buckets=(8, 16),
    )
    assert run.frames == (ObservedFrame(1, 8), ObservedFrame(4, 16))
    assert run.deliveries == (("a", 1), ("b", 4))


def test_request_larger_than_last_bucket_is_invalid() -> None:
    with pytest.raises(ValueError, match="no configured bucket"):
        simulate_padding_only(
            [ReleaseRequest("x", 0, 1, 13)], horizon=2, crypto_bytes=4, buckets=(8, 16)
        )
