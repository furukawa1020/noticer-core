import json
from dataclasses import asdict

import pytest

from noticer_core.receipt_limit_fixtures import crossed_recipients
from noticer_core.receipt_limit_tapes import decode_histories


def test_private_eligibility_can_change_but_public_fields_cannot():
    problem = crossed_recipients()
    data = json.loads(json.dumps(asdict(problem)))
    assert decode_histories(data["worlds"], data["recipients"]) == problem
    data["worlds"][0]["actions"][0]["deadline"] = 0
    data["worlds"][0]["actions"][0]["slots"] = [0]
    with pytest.raises(ValueError, match="public"):
        decode_histories(data["worlds"], data["recipients"])
