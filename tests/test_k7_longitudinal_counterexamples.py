from dataclasses import replace
from typing import Any

import pytest

from noticer_core.evaluation.certificate_compatibility import check_compatibility
from noticer_core.evaluation.public_handoff import (
    HandoffValidationError,
    PublicHandoffContract,
    PublicHandoffState,
    ResourceBounds,
    contract_from_document,
)


def _contract(incoming: bool) -> PublicHandoffContract:
    return PublicHandoffContract(
        "noticer.k7.public-handoff.v1", "in" if incoming else "out",
        "a" * 64, "b" * 64, ("d" if incoming else "c") * 64,
        PublicHandoffState("e" * 64, ("alpha", "beta"), "epoch", "key",
                           0 if incoming else 5),
        ResourceBounds(7 if incoming else 5, 10, 1, 1),
    )


def _document() -> dict[str, Any]:
    return {
        "format_version": "noticer.k7.public-handoff.v1",
        "contract_id": "boundary",
        "action_semantics_sha256": "a" * 64,
        "observer_contract_sha256": "b" * 64,
        "source_certificate_sha256": "c" * 64,
        "state": {"observer_state_sha256": "e" * 64,
                  "colluding_services": ["alpha", "beta"],
                  "epoch_id": "epoch", "key_epoch_id": "key",
                  "epoch_event_slot": 5},
        "bounds": {"horizon_slots": 5, "max_queries": 10,
                   "max_retries": 1, "max_failures": 1},
    }


def test_handoff_state_mismatch_is_rejected() -> None:
    left, right = _contract(False), _contract(True)
    right = replace(right, state=replace(
        right.state, observer_state_sha256="f" * 64))
    assert check_compatibility(left, right).mismatch_reasons == ("observer_state",)


@pytest.mark.parametrize("field", ["private_cache", "secret_retry", "private_epoch"])
def test_private_carryover_is_structurally_rejected(field: str) -> None:
    document = _document()
    document["state"][field] = "hidden-across-buckets"
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(document)
    assert caught.value.category == "forbidden_private_carryover"


def test_service_collusion_change_is_rejected() -> None:
    left, right = _contract(False), _contract(True)
    right = replace(right, state=replace(
        right.state, colluding_services=("alpha",)))
    assert check_compatibility(left, right).mismatch_reasons == ("service_collusion",)


def test_epoch_change_must_use_declared_public_fields() -> None:
    public = _document()
    public["state"]["epoch_id"] = "epoch-next"
    public["state"]["key_epoch_id"] = "key-next"
    assert contract_from_document(public).state.epoch_id == "epoch-next"
    secret = _document()
    secret["state"]["secret_epoch"] = "epoch-next"
    with pytest.raises(HandoffValidationError) as caught:
        contract_from_document(secret)
    assert caught.value.category == "forbidden_private_carryover"
