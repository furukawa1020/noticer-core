import json

import pytest

from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_tape_codec import decode_tapes, encode_tapes


def test_tape_codec_roundtrips_without_accepting_hidden_fields():
    game = asymmetric_game()
    data = json.loads(json.dumps(encode_tapes(game)))
    assert decode_tapes(data) == game
    data[0]["private_readiness"] = 4
    with pytest.raises(ValueError, match="shape"):
        decode_tapes(data)
