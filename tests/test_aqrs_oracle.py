from __future__ import annotations

from copy import deepcopy
from typing import Any

from noticer_core.evaluation.aqrs_oracle import (
    CheckLimits,
    MutationCase,
    OracleMutation,
    check_document,
    model_from_document,
    run_mutation_campaign,
)


def _release(
    *,
    emitted: bool = True,
    fields: dict[str, str] | None = None,
    actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "emitted": emitted,
        "fields": fields or {},
        "actions": actions or [],
    }


def _authorized(identifier: str, action: str) -> dict[str, Any]:
    return {
        "obligation": {"kind": "authorized", "id": identifier},
        "action": action,
    }


def _recovery(fault: str, slot: int, action: str) -> dict[str, Any]:
    return {
        "obligation": {
            "kind": "recovery",
            "fault": fault,
            "triggered_at": slot,
        },
        "action": action,
    }


def base_document(*, horizon: int = 1) -> dict[str, Any]:
    return {
        "format_version": "aqrs-check-model-v1",
        "horizon": horizon,
        "states": [
            {
                "id": "left",
                "action_semantics": "same-action",
                "private_history": "private-a",
            },
            {
                "id": "right",
                "action_semantics": "same-action",
                "private_history": "private-b",
            },
        ],
        "semantics": [{"id": "same-action", "obligations": []}],
        "faults": [],
        "inputs": [{"id": "tick", "public_symbol": "tick", "fault": None}],
        "transitions": [
            {
                "from": "left",
                "input": "tick",
                "to": "left",
                "release": _release(),
            },
            {
                "from": "right",
                "input": "tick",
                "to": "right",
                "release": _release(),
            },
        ],
        "observers": [
            {
                "id": "network",
                "visible_fields": [],
                "observes_actions": True,
            }
        ],
        "initial_pairs": [{"left": "left", "right": "right"}],
    }


def _set_releases(
    document: dict[str, Any], left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    document["transitions"][0]["release"] = left
    document["transitions"][1]["release"] = right
    return document


def _set_obligations(
    document: dict[str, Any], obligations: list[dict[str, Any]]
) -> dict[str, Any]:
    document["semantics"][0]["obligations"] = obligations
    return document


def test_verified_model_and_visible_leak_have_stable_outcomes() -> None:
    verified = check_document(base_document(horizon=2))
    assert verified.status == "verified"
    assert verified.checked_horizon == 2

    leaky = base_document(horizon=2)
    leaky["observers"][0]["visible_fields"] = ["bucket"]
    _set_releases(
        leaky,
        _release(fields={"bucket": "a"}),
        _release(fields={"bucket": "b"}),
    )
    counterexample = check_document(leaky)
    assert counterexample.status == "counterexample"
    assert counterexample.category == "security_divergence"
    assert counterexample.causal_field == "field:bucket"
    assert counterexample.slot == 0
    assert len(counterexample.trace) == 1


def test_invalid_and_resource_limited_models_never_become_verified() -> None:
    invalid = base_document()
    invalid["transitions"].pop()
    outcome = check_document(invalid)
    assert outcome.status == "invalid"
    assert outcome.category == "missing_transition"

    limited = check_document(base_document(horizon=2), CheckLimits(max_nodes=0))
    assert limited.status == "inconclusive"
    assert limited.reason == "node_limit"


def test_utility_and_fault_failures_remain_distinguishable() -> None:
    unauthorized = _set_releases(
        base_document(),
        _release(actions=[_authorized("forged", "unlock")]),
        _release(actions=[_authorized("forged", "unlock")]),
    )
    unauthorized_outcome = check_document(unauthorized)
    assert unauthorized_outcome.category == "unauthorized_action"
    assert unauthorized_outcome.obligation == "authorized:forged"

    deadline = _set_obligations(
        base_document(),
        [{"id": "permit", "action": "notify", "trigger_slot": 0, "deadline_slot": 0}],
    )
    assert check_document(deadline).category == "missed_deadline"

    fault = base_document()
    fault["faults"] = [
        {
            "id": "link-loss",
            "recovery": {"action": "safe-fallback", "deadline_after_slots": 0},
        }
    ]
    fault["inputs"][0]["fault"] = "link-loss"
    _set_releases(
        fault,
        _release(actions=[_recovery("link-loss", 0, "unsafe-retry")]),
        _release(actions=[_recovery("link-loss", 0, "unsafe-retry")]),
    )
    fault_outcome = check_document(fault)
    assert fault_outcome.category == "unauthorized_action"
    assert fault_outcome.obligation == "recovery:link-loss@0"


def test_mutation_campaign_kills_all_ten_checker_mutants() -> None:
    presence = _set_releases(
        base_document(), _release(emitted=False), _release(emitted=True)
    )

    field = base_document()
    field["observers"][0]["visible_fields"] = ["bucket"]
    _set_releases(
        field,
        _release(fields={"bucket": "a"}),
        _release(fields={"bucket": "b"}),
    )

    actions = _set_obligations(
        base_document(),
        [
            {"id": "left-permit", "action": "left", "trigger_slot": 0, "deadline_slot": 0},
            {"id": "right-permit", "action": "right", "trigger_slot": 0, "deadline_slot": 0},
        ],
    )
    _set_releases(
        actions,
        _release(actions=[_authorized("left-permit", "left")]),
        _release(actions=[_authorized("right-permit", "right")]),
    )

    left_utility = base_document()
    left_utility["observers"][0]["observes_actions"] = False
    _set_releases(
        left_utility,
        _release(actions=[_authorized("forged", "unlock")]),
        _release(),
    )
    right_utility = deepcopy(left_utility)
    _set_releases(
        right_utility,
        _release(),
        _release(actions=[_authorized("forged", "unlock")]),
    )

    duplicate = _set_obligations(
        base_document(horizon=2),
        [{"id": "permit", "action": "notify", "trigger_slot": 0, "deadline_slot": 1}],
    )
    _set_releases(
        duplicate,
        _release(actions=[_authorized("permit", "notify")]),
        _release(actions=[_authorized("permit", "notify")]),
    )

    deadline = _set_obligations(
        base_document(),
        [{"id": "permit", "action": "notify", "trigger_slot": 0, "deadline_slot": 0}],
    )

    recovery = base_document()
    recovery["faults"] = [
        {
            "id": "link-loss",
            "recovery": {"action": "safe-fallback", "deadline_after_slots": 0},
        }
    ]
    recovery["inputs"][0]["fault"] = "link-loss"

    cases = {
        OracleMutation.OMIT_RELEASE_PRESENCE: MutationCase(
            model_from_document(presence)
        ),
        OracleMutation.OMIT_VISIBLE_FIELDS: MutationCase(model_from_document(field)),
        OracleMutation.OMIT_OBSERVED_ACTIONS: MutationCase(
            model_from_document(actions)
        ),
        OracleMutation.SUPPRESS_LEFT_UTILITY: MutationCase(
            model_from_document(left_utility)
        ),
        OracleMutation.SUPPRESS_RIGHT_UTILITY: MutationCase(
            model_from_document(right_utility)
        ),
        OracleMutation.ACCEPT_UNKNOWN_OBLIGATION: MutationCase(
            model_from_document(left_utility)
        ),
        OracleMutation.ACCEPT_DUPLICATE_ACTION: MutationCase(
            model_from_document(duplicate)
        ),
        OracleMutation.SUPPRESS_AUTHORIZED_DEADLINE: MutationCase(
            model_from_document(deadline)
        ),
        OracleMutation.SUPPRESS_RECOVERY_ACTIVATION: MutationCase(
            model_from_document(recovery)
        ),
        OracleMutation.PROMOTE_NODE_LIMIT: MutationCase(
            model_from_document(base_document(horizon=2)), CheckLimits(max_nodes=0)
        ),
    }
    results = run_mutation_campaign(cases)
    assert len(results) == 10
    assert all(result.killed for result in results)
