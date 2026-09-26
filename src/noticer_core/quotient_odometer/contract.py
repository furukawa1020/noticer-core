"""Frozen QuotientOdometer research-contract validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT_ID = "QUOTIENT_ODOMETER_FROZEN_EVAL_V1"
ALPHA_ORDERS = [2, 3, 4, 8, 16, 32, 64]
ATTACKS = [f"A{i}_" for i in range(10)]
REQUIRED_HELD_OUT = {
    "ADAPTIVE_MECHANISM_SELECTION",
    "CONCURRENT_SERVICE",
    "COLLUSION",
    "MODEL_CHANGE",
    "CRASH",
}


class ContractError(ValueError):
    """Raised when a frozen contract violates a preregistered invariant."""


def load_contract(path: Path) -> dict[str, Any]:
    """Load and validate a UTF-8 JSON QuotientOdometer contract."""
    with path.open("r", encoding="utf-8-sig") as handle:
        contract: dict[str, Any] = json.load(handle)
    validate_contract(contract)
    return contract


def validate_contract(contract: dict[str, Any]) -> None:
    """Reject mutations that weaken the frozen evaluation protocol."""
    _require(contract.get("contract_id") == CONTRACT_ID, "contract_id changed")
    _require(
        contract.get("status") == "FROZEN_BEFORE_IMPLEMENTATION",
        "contract is not frozen before implementation",
    )
    quantity = _mapping(contract, "quantity")
    _require(
        quantity.get("infinite_on_support_mismatch") is True, "support mismatch must be infinite"
    )
    _require(
        quantity.get("does_not_charge") == "authorized_action_semantics",
        "authorized actions must not be double charged",
    )
    profile = _mapping(contract, "profile")
    _require(profile.get("alpha_orders") == ALPHA_ORDERS, "alpha grid changed")
    _require(
        set(profile.get("directions", [])) == {"P0_TO_P1", "P1_TO_P0"},
        "bidirectional profile required",
    )
    _require(profile.get("rounding") == "DIRECTED_UPPER", "upper rounding required")
    _require(profile.get("overflow") == "FAIL_CLOSED", "overflow must fail closed")
    _require(
        "EMPIRICAL_LAB_ONLY" not in profile.get("production_derivations", []),
        "empirical profile cannot enter production",
    )
    budget = _mapping(contract, "budget")
    _require(budget.get("delta_target") == "1/1000000", "target delta changed")
    _require(budget.get("maximum_epsilon_q16_16") == 131072, "epsilon budget changed")
    _require(budget.get("maximum_releases") == 10000, "release budget changed")
    _require(budget.get("all_representations_must_pass") is True, "all budget forms must pass")
    attacks = contract.get("adaptive_attacks", [])
    _require(len(attacks) == 10, "ten adaptive attacks required")
    for prefix in ATTACKS:
        _require(any(str(attack).startswith(prefix) for attack in attacks), f"missing {prefix}")
    outcomes = _mapping(contract, "required_attack_outcomes")
    _require(
        outcomes and all(value == 0 for value in outcomes.values()), "bypass targets must be zero"
    )
    benchmark = _mapping(contract, "benchmark")
    _require(benchmark.get("minimum_families", 0) >= 24, "minimum 24 families required")
    _require(benchmark.get("split_unit") == "BENCHMARK_FAMILY", "family-disjoint split required")
    _require(benchmark.get("variant_overlap_allowed") is False, "variant overlap forbidden")
    _require(
        REQUIRED_HELD_OUT <= set(benchmark.get("held_out_required", [])),
        "required held-out families missing",
    )
    _require(benchmark.get("evaluation_releases") == 10000, "evaluation release count changed")
    baselines = set(contract.get("baselines", []))
    _require(
        len(baselines) == 8 and "M_QUOTIENT_ODOMETER" in baselines, "baseline registry changed"
    )
    metrics = _mapping(contract, "metrics")
    for family in ("privacy", "utility", "runtime_safety"):
        _require(bool(metrics.get(family)), f"missing {family} metrics")
    claims = _mapping(contract, "claims")
    _require(
        "world-first privacy accountant" in claims.get("forbidden", []), "world-first ban missing"
    )
    policy = _mapping(contract, "artifact_policy")
    for key in (
        "forbid_private_biosignal",
        "forbid_baseline",
        "forbid_identity",
        "forbid_exact_private_timing",
    ):
        _require(policy.get(key) is True, f"artifact policy weakened: {key}")
    _require(
        policy.get("generated_artifacts_committed") is False, "generated artifacts must stay out"
    )


def _mapping(contract: dict[str, Any], key: str) -> dict[str, Any]:
    value = contract.get(key)
    _require(isinstance(value, dict), f"{key} must be an object")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)
