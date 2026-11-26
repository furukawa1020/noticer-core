from noticer_core.shared_slot_branch import crossed_public_futures, public_first_view


def test_visible_prefix_does_not_identify_the_future():
    left, right = crossed_public_futures()
    assert public_first_view(left) == public_first_view(right)
    assert left != right
    assert left.actions[0].slots == (0, 1)
    assert right.actions[0].slots == (0,)
