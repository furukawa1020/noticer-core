import pytest

from noticer_core.slot_mix_masks import maximal_masks, tape_mask


def test_strict_supersets_dominate_and_ties_are_deterministic():
    assert maximal_masks((0b101, 0b001, 0b110, 0b110, 0)) == (0b101, 0b110)
    assert maximal_masks((0,)) == (0,)
    assert tape_mask((4, 1, 4)) == 0b10010
    with pytest.raises(ValueError):
        tape_mask((True,))
