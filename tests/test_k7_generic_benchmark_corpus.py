from __future__ import annotations

import struct
from hashlib import sha256
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.benchmark_case import (
    benchmark_case_manifest,
    load_benchmark_case,
    verify_aqrs_source_binding,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "configs" / "quotient_forge" / "benchmark_cases" / "generic"
REGISTRY = ROOT / "configs" / "quotient_forge" / "benchmark_family_registry_v1.yaml"

EXPECTED = {
    "generic_delayed_notification": ("train", 3, 1, 2, 2),
    "generic_fixed_size_release": ("train", 2, 1, 2, 4),
    "generic_public_retry": ("train", 3, 2, 2, 3),
    "generic_private_scheduler": ("development", 4, 1, 2, 3),
    "generic_medical_alert": ("development", 4, 2, 2, 3),
    "generic_smart_home_actuator": ("held_out", 4, 2, 2, 3),
    "generic_activity_actuator": ("held_out", 5, 2, 2, 3),
    "generic_fault_tolerant_alarm": ("held_out", 5, 3, 2, 5),
}


def template_digest(horizon: int, symbols: int) -> str:
    payload = bytearray(struct.pack("<II", horizon, symbols))
    for state in range(horizon):
        for _ in range(symbols):
            payload.extend(
                struct.pack("<II", min(state + 1, horizon - 1), int(state == horizon - 1))
            )
    return sha256(payload).hexdigest()


@pytest.mark.parametrize("family_id", EXPECTED)
def test_generic_case_source_binding_and_dimensions(family_id: str) -> None:
    split, horizon, symbols, observer_count, observer_dimensions = EXPECTED[family_id]
    case = load_benchmark_case(CORPUS / f"{family_id}.yaml")
    verify_aqrs_source_binding(case, (CORPUS / f"{family_id}.qf").read_bytes())
    assert case.family_id == family_id
    assert case.variant_id == "canonical"
    assert case.split == split
    assert case.dimensions.plant_states == 2 * horizon
    assert case.dimensions.plant_transitions == 2 * horizon * symbols
    assert case.dimensions.machine_state_bound == horizon
    assert case.dimensions.machine_symbol_count == symbols
    assert case.dimensions.observer_count == observer_count
    assert case.dimensions.observer_dimensions == observer_dimensions
    if split == "held_out":
        assert case.author_template_sha256 is None
    else:
        assert case.author_template_sha256 == template_digest(horizon, symbols)
    assert benchmark_case_manifest(case)["privacy"]["private_biosignal_field_count"] == 0


def test_generic_corpus_matches_the_locked_family_splits() -> None:
    registry = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    locked = {
        family["id"]: family["split"]
        for family in registry["families"]
        if family["category"] == "generic"
    }
    actual = {
        family_id: load_benchmark_case(CORPUS / f"{family_id}.yaml").split for family_id in EXPECTED
    }
    assert actual == locked
    assert len(list(CORPUS.glob("*.yaml"))) == 8
    assert len(list(CORPUS.glob("*.qf"))) == 8


def test_generic_corpus_covers_reactive_privacy_boundaries() -> None:
    cases = [load_benchmark_case(CORPUS / f"{family_id}.yaml") for family_id in EXPECTED]
    tags = {tag for case in cases for tag in case.feature_tags}
    obligations = {obligation for case in cases for obligation in case.obligations}
    assert {"failure", "retry", "silence", "size", "timing"} <= tags
    assert {"action_window", "bounded_loss", "exactly_once", "reconnect"} <= obligations
    scheduler = (CORPUS / "generic_private_scheduler.qf").read_text(encoding="utf-8")
    assert "schedule_choice" in scheduler
    assert "erase schedule_choice" in scheduler
