import json

import pytest

from noticer_core.slot_mix_bundle import export_bundle, parse_bundle
from noticer_core.slot_mix_certificate import verify_mix
from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_frontier import WorkBudget
from noticer_core.slot_mix_solve import solve_mix


def test_portable_bundle_rejects_semantic_and_syntactic_tampering():
    game = asymmetric_game()
    cert = solve_mix(game).certificate
    assert cert is not None
    data = json.loads(export_bundle(game, cert))
    data["model"] = "tape-selected-after-draw"
    with pytest.raises(ValueError, match="model"):
        parse_bundle(json.dumps(data).encode())
    data = json.loads(export_bundle(game, cert))
    data["tape_weights"] = ["1/4"] * 4
    forged_game, forged_certificate = parse_bundle(json.dumps(data).encode())
    assert not verify_mix(forged_game, forged_certificate, WorkBudget(1000))
