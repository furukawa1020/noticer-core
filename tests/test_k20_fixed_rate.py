import pytest

from noticer_core.evaluation.k20_fixed_rate import simulate_fixed_rate
from noticer_core.evaluation.k20_release_reference import ObservedFrame, ReleaseRequest


def test_cadence_and_size_do_not_depend_on_queue() -> None:
    settings = {"horizon": 5, "period": 2, "frame_bytes": 16, "crypto_bytes": 4}
    empty = simulate_fixed_rate([], **settings)
    filled = simulate_fixed_rate(
        [ReleaseRequest("a", 1, 1, 2), ReleaseRequest("b", 4, 4, 7),
         ReleaseRequest("c", 4, 4, 7)], **settings
    )
    assert empty.frames == filled.frames == tuple(ObservedFrame(i, 16) for i in (0, 2, 4))
    assert filled.deliveries == (("a", 2), ("b", 4))
    assert filled.undelivered == ("c",)


def test_oversize_frame_is_not_silently_dropped() -> None:
    with pytest.raises(ValueError, match="too small"):
        simulate_fixed_rate(
            [ReleaseRequest("a", 0, 0, 5)],
            horizon=4, period=1, frame_bytes=8, crypto_bytes=4,
        )
