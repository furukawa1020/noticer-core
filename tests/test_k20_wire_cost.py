import pytest

from noticer_core.evaluation.k20_wire_cost import WireEvent, summarize_wire_cost


def test_wire_bytes_include_cover_traffic_and_retries_once() -> None:
    summary = summarize_wire_cost([WireEvent(10, 20, 3, True), WireEvent(0, 40, 5)])
    assert summary.events == 2
    assert summary.wire_bytes == 78
    assert summary.retransmitted_bytes == 33
    assert summary.padding_fraction == pytest.approx(60 / 78)


def test_empty_wire_observation_has_no_padding_ratio() -> None:
    assert summarize_wire_cost([]).padding_fraction is None


def test_negative_byte_components_are_not_cancelled_by_other_bytes() -> None:
    with pytest.raises(ValueError, match="nonnegative"):
        summarize_wire_cost([WireEvent(10, -5, 1)])
