from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from noticer_core.quotient_odometer import ContractError, load_contract, validate_contract

CONTRACT_PATH = Path("specs/quotient_odometer/frozen_contract.json")


def contract() -> dict[str, object]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8-sig"))


def test_canonical_contract_is_valid() -> None:
    loaded = load_contract(CONTRACT_PATH)
    assert loaded["contract_id"] == "QUOTIENT_ODOMETER_FROZEN_EVAL_V1"


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("profile", "alpha_orders"), [2, 4, 8], "alpha grid changed"),
        (("budget", "maximum_epsilon_q16_16"), 196608, "epsilon budget changed"),
        (("benchmark", "variant_overlap_allowed"), True, "variant overlap forbidden"),
        (("quantity", "infinite_on_support_mismatch"), False, "support mismatch must be infinite"),
        (("artifact_policy", "forbid_exact_private_timing"), False, "artifact policy weakened"),
    ],
)
def test_security_weakening_mutations_are_rejected(
    path: tuple[str, str], value: object, message: str
) -> None:
    mutated = copy.deepcopy(contract())
    section = mutated[path[0]]
    assert isinstance(section, dict)
    section[path[1]] = value
    with pytest.raises(ContractError, match=message):
        validate_contract(mutated)


def test_every_attack_and_negative_target_is_frozen() -> None:
    frozen = contract()
    attacks = frozen["adaptive_attacks"]
    outcomes = frozen["required_attack_outcomes"]
    assert isinstance(attacks, list) and len(attacks) == 10
    assert isinstance(outcomes, dict) and all(value == 0 for value in outcomes.values())


def test_split_is_family_disjoint_and_contains_hard_cases() -> None:
    frozen = contract()
    benchmark = frozen["benchmark"]
    assert isinstance(benchmark, dict)
    assert benchmark["split_unit"] == "BENCHMARK_FAMILY"
    assert benchmark["variant_overlap_allowed"] is False
    assert set(benchmark["held_out_required"]) >= {
        "ADAPTIVE_MECHANISM_SELECTION",
        "CONCURRENT_SERVICE",
        "COLLUSION",
        "MODEL_CHANGE",
        "CRASH",
    }
