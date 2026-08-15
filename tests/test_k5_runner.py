import json
from pathlib import Path

import pytest

from tools.run_k5_provenance import (
    GateResult,
    find_private_fields,
    load_config_bundle,
    validate_public_artifact,
    write_gate_manifest,
)


def test_committed_k5_configs_remain_non_hardware_claims() -> None:
    bundle = load_config_bundle(Path("configs/k5"))
    assert bundle.synthetic["seed"] == 20260814
    assert bundle.polar["sdk_version"] == "8.1.0"
    assert bundle.polar["hardware_status"] == "NOT_VERIFIED"
    assert bundle.hardware["tier_d"] == "NOT_VERIFIED"


def test_private_field_validator_uses_exact_paths() -> None:
    assert find_private_fields({"public": {"device_id": "forbidden"}}) == [
        "$.public.device_id"
    ]
    assert find_private_fields({"private_field_count": 0}) == []


def test_gate_manifest_contains_no_commands_or_output(tmp_path: Path) -> None:
    manifest = tmp_path / "software_gates.json"
    write_gate_manifest([GateResult("gate-a", True)], manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload == {
        "schema": "noticer-k5-software-gates-v1",
        "all_passed": True,
        "gates": [{"id": "gate-a", "status": "PASSED"}],
    }


def test_public_artifact_rejects_hardware_overclaim(tmp_path: Path) -> None:
    artifact = {
        "schema": "noticer-k5-tier-a-public-v1",
        "decision": "GO_TIER_A",
        "private_field_count": 0,
        "hardware_tiers": [
            {"tier": "B", "status": "VERIFIED"},
            {"tier": "C", "status": "NOT_VERIFIED"},
            {"tier": "D", "status": "NOT_VERIFIED"},
        ],
    }
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    with pytest.raises(ValueError, match="Hardware tiers"):
        validate_public_artifact(path)

