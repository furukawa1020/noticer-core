from noticer_core.slot_mix_terminal import delivery_status


def test_success_requires_all_deliveries_by_inclusive_deadline():
    deadlines = {"a": 0, "b": 1}
    assert delivery_status((), deadlines, 0) == "complete"
    assert delivery_status(("a",), deadlines, 0) == "expired"
    assert delivery_status(("b",), deadlines, 0) == "continue"
    assert delivery_status(("b",), deadlines, 1) == "expired"
