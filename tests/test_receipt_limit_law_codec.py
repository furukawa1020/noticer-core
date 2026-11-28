from fractions import Fraction

import pytest

from noticer_core.receipt_limit_law_codec import decode_law


def test_exact_laws_reject_float_and_invalid_slot_type():
    assert decode_law([{"plan": [["a", 0]], "mass": "1/2"}]) == (((("a", 0),), Fraction(1, 2)),)
    for row in ({"plan": [["a", False]], "mass": "1"}, {"plan": [], "mass": 1.0}):
        with pytest.raises(ValueError):
            decode_law([row])
