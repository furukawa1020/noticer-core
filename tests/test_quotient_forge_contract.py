from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "configs" / "quotient_forge" / "contract.toml"


def _contract() -> dict[str, object]:
    with CONTRACT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def test_resource_limits_are_bounded_and_frozen() -> None:
    limits = _contract()["limits"]
    assert limits == {
        "max_source_bytes": 1_000_000,
        "max_states": 256,
        "max_transitions": 100_000,
        "max_horizon": 512,
        "max_observers": 16,
        "max_cegis_iterations": 10_000,
        "max_solver_seconds": 300,
        "max_memory_mb": 4_096,
    }


def test_hash_domains_are_unique_and_versioned() -> None:
    domains = _contract()["hash_domains"]
    values = list(domains.values())
    assert len(values) == len(set(values))
    assert all(value.startswith("QUOTIENT_FORGE_") for value in values)
    assert all(value.endswith("_V1") for value in values)


def test_security_and_utility_are_hard_constraints() -> None:
    constraints = _contract()["hard_constraints"]
    assert constraints
    assert all(constraints.values())


def test_outcome_classes_are_disjoint() -> None:
    outcomes = _contract()["outcomes"]
    groups = [set(values) for values in outcomes.values()]
    flattened = set().union(*groups)
    assert sum(len(group) for group in groups) == len(flattened)
    assert outcomes["success"] == ["CERTIFICATE_VALID"]
    assert "TIMEOUT" in outcomes["inconclusive"]
    assert "UNSAT_AT_BOUND" in outcomes["bounded_negative"]
    assert "UNREALIZABLE_WITHIN_BOUNDS" in outcomes["bounded_negative"]
