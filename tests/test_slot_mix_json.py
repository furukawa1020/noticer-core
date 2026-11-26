import pytest

from noticer_core.slot_mix_json import MAX_BUNDLE_BYTES, decode_json


@pytest.mark.parametrize(
    "raw",
    [b'{"a":1,"a":2}', b'{"a":NaN}', b"\xff", b"[" * 2000, b"x" * (MAX_BUNDLE_BYTES + 1)],
    ids=("duplicate", "nonfinite", "non-utf8", "deep", "oversize"),
)
def test_noncanonical_or_unbounded_json_is_rejected(raw):
    with pytest.raises(ValueError):
        decode_json(raw)
