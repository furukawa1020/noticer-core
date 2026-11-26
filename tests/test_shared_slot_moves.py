from noticer_core.shared_slot_moves import legal_moves, remaining_after


def test_legal_moves_include_wait_but_exclude_unavailable_actions():
    assert legal_moves(("a", "b", "c"), ("b", "c", "d"), 2) == (
        ("b", "c"), ("b",), ("c",), ()
    )
    assert legal_moves(("a",), ("a",), 0) == ((),)
    assert remaining_after(("a", "b", "c"), ("b", "c")) == ("a",)
