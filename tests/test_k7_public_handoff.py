from copy import deepcopy
from typing import Any

import pytest

from noticer_core.evaluation.public_handoff import (
    HandoffValidationError,
    canonical_contract_json,
    contract_digest,
    contract_from_document,
)


def _document() -> dict[str, Any]:
    return {
        "format_version": "noticer.k7.public-handoff.v1",
        "contract_id": "alpha-to-beta",
        "action_semantics_sha256": "a" * 64,
        "observer_contract_sha256": "b" * 64,
        "source_certificate_sha256": "c" * 64,
        "state": {"observer_state_sha256": "d" * 64,
                  "colluding_services": ["alpha", "beta"],
                  "epoch_id": "epoch-7", "key_epoch_id": "key-epoch-7",
                  "epoch_event_slot": 5},
        "bounds": {"horizon_slots": 5, "max_queries": 64,
                   "max_retries": 2, "max_failures": 1},
    }


def test_contract_is_closed_and_deterministic() -> None:
    first = contract_from_document(_document())
    second = contract_from_document(deepcopy(_document()))
    assert first == second
    assert contract_digest(first) == contract_digest(second)
    assert canonical_contract_json(first).endswith(b"\n")


@pytest.mark.parametrize("key", ["private_cache", "private_history",
                                 "secret_retry", "raw_biosignal"])
def test_private_carryover_is_rejected(key: str) -> None:
    document = _document()
    document["state"][key] = "must-not-cross"
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(document)
    assert caught.value.category == "forbidden_private_carryover"


def test_smuggling_and_noncanonical_collusion_are_rejected() -> None:
    extra = _document()
    extra["state"]["debug"] = "undeclared"
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(extra)
    assert caught.value.category == "undeclared_field"
    unordered = _document()
    unordered["state"]["colluding_services"] = ["beta", "alpha", "alpha"]
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(unordered)
    assert caught.value.category == "noncanonical_services"


def test_bounds_and_bindings_are_checked() -> None:
    outside = _document()
    outside["state"]["epoch_event_slot"] = 6
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(outside)
    assert caught.value.category == "event_out_of_bounds"
    bad_digest = _document()
    bad_digest["observer_contract_sha256"] = "bad"
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(bad_digest)
    assert caught.value.category == "invalid_digest"
