import pytest

from noticer_core.shared_slot_cover import CoverWitness, fixed_allocation_cover


def test_opposite_fixed_shapes_require_one_dummy_each():
    assert fixed_allocation_cover(((1, 0), (0, 1))) == CoverWitness((1, 1), (1, 1))
    assert fixed_allocation_cover(((1, 0), (1, 0))) == CoverWitness((1, 0), (0, 0))
    with pytest.raises(ValueError, match="counts"):
        fixed_allocation_cover(((True, 0), (1, 0)))
