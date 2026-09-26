from __future__ import annotations

import tomllib
from pathlib import Path

CONTRACT = Path("configs/quotient_guard/k10_qg_research_v1.toml")


def load_contract() -> dict[str, object]:
    return tomllib.loads(CONTRACT.read_text(encoding="utf-8-sig"))


def test_contract_is_frozen_before_results() -> None:
    contract = load_contract()
    assert contract["schema"] == "noticer.quotient-guard.research-contract.v1"
    assert contract["status"] == "FROZEN_BEFORE_RESULTS"
    assert contract["hardware_claim"] == "NOT_VERIFIED"
    assert contract["parent_issue"] == 479


def test_private_and_public_state_are_disjoint() -> None:
    state = load_contract()["state"]
    assert set(state["private"]).isdisjoint(state["public"])
    assert set(state["prohibited_public"]).isdisjoint(state["public"])
    assert "private_readiness" in state["prohibited_public"]
    assert "stable_identifier" in state["prohibited_public"]


def test_observer_fault_and_outcome_taxonomies_are_fixed() -> None:
    contract = load_contract()
    assert len(contract["observers"]["required"]) == 6
    assert len(contract["faults"]["required"]) == 9
    assert len(contract["outcomes"]["classes"]) == 6
    assert contract["outcomes"]["only_success"] == "RUNNING_VALID"


def test_fail_closed_has_no_automatic_recovery() -> None:
    fail_closed = load_contract()["fail_closed"]
    assert fail_closed["sink_public_action"] == "NO_RELEASE"
    assert fail_closed["automatic_recovery"] is False
    assert set(fail_closed["recovery_requires"]) == {
        "NEW_VERIFIED_CAPSULE",
        "EPOCH_INCREMENT",
        "EXPLICIT_PUBLIC_RESET",
    }


def test_evaluation_and_resource_bounds_are_nontrivial() -> None:
    contract = load_contract()
    assert contract["minimums"]["mutation_rejection_percent"] == 100
    assert contract["minimums"]["longitudinal_slots"] >= 4096
    assert contract["limits"]["max_clock_skew_ms"] == 250
    assert contract["limits"]["max_monitor_states"] == 1_000_000


def test_artifact_and_claim_boundaries_are_explicit() -> None:
    contract = load_contract()
    assert contract["artifacts"]["generated_committed"] is False
    assert "raw_biosignal" in contract["artifacts"]["prohibited"]
    assert "medical_decision" in contract["non_goals"]["values"]
    assert "world-first" not in CONTRACT.read_text(encoding="utf-8-sig").lower()
