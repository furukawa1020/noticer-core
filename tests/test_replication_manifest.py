from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from noticer_core.replication.manifest import (
    MANIFEST_SCHEMA,
    ManifestError,
    build_manifest,
    canonical_json,
    load_spec,
    resolve_repository_file,
    verify_manifest,
    write_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "replication" / "manifest_spec_v1.json"


def test_manifest_is_deterministic_and_fully_recomputable() -> None:
    first = build_manifest(ROOT, SPEC)
    second = build_manifest(ROOT, SPEC)

    assert first == second
    assert canonical_json(first) == canonical_json(second)
    assert first["schema"] == MANIFEST_SCHEMA
    assert len(first["artifact_sha256"]) == 64
    verify_manifest(ROOT, first)


def test_manifest_freezes_all_required_toolchains_and_k7_dependencies() -> None:
    manifest = build_manifest(ROOT, SPEC)

    assert {item["name"]: item["version"] for item in manifest["toolchains"]} == {
        "lean": "4.30.0",
        "node": "24",
        "python": "3.11",
        "rust": "1.93.0",
        "wasm-target": "wasm32-unknown-unknown",
    }
    assert [item["issue"] for item in manifest["k7_dependencies"]] == [76, 77, 88]
    assert all(len(item["commit"]) == 40 for item in manifest["k7_dependencies"])


def test_inventory_is_posix_sorted_bounded_and_digest_addressed() -> None:
    manifest = build_manifest(ROOT, SPEC)
    paths = [item["path"] for item in manifest["inventory"]]

    assert paths == sorted(paths)
    assert all("\\" not in path and ".." not in Path(path).parts for path in paths)
    assert all(len(item["sha256"]) == 64 for item in manifest["inventory"])
    assert {"LOCKFILE", "CONFIG", "SCHEMA", "SOURCE", "FORMAL", "DOC"} <= {
        item["kind"] for item in manifest["inventory"]
    }


def test_unknown_fields_and_path_escape_fail_closed(tmp_path: Path) -> None:
    value = json.loads(SPEC.read_text(encoding="utf-8"))
    value["unexpected"] = True
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ManifestError, match="fields mismatch"):
        load_spec(malformed)
    with pytest.raises(ManifestError, match="canonical"):
        resolve_repository_file(ROOT, "../outside")
    with pytest.raises(ManifestError, match="POSIX"):
        resolve_repository_file(ROOT, "configs\\quotient_seal\\k8_research.yaml")


def test_tampered_manifest_digest_and_inventory_are_rejected() -> None:
    manifest = build_manifest(ROOT, SPEC)
    tampered_digest = copy.deepcopy(manifest)
    tampered_digest["artifact_sha256"] = "0" * 64
    with pytest.raises(ManifestError, match="artifact digest mismatch"):
        verify_manifest(ROOT, tampered_digest)

    tampered_inventory = copy.deepcopy(manifest)
    tampered_inventory["inventory"][0]["bytes"] += 1
    with pytest.raises(ManifestError, match="artifact digest mismatch"):
        verify_manifest(ROOT, tampered_inventory)


def test_generated_output_is_utf8_and_stays_under_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "artifacts" / "replication" / "manifest.json"
    manifest = write_manifest(ROOT, SPEC, output)

    assert output.read_bytes() == canonical_json(manifest)
    assert output.parent.name == "replication"
    assert manifest["hardware_status"] == "NOT_VERIFIED"
    assert manifest["security_interpretation"] == "NOT_A_SECURITY_VERDICT"


def test_manifest_contains_no_sensitive_values_or_priority_claim() -> None:
    encoded = canonical_json(build_manifest(ROOT, SPEC)).decode("utf-8").lower()

    assert "world-first" not in encoded
    assert "subject_id" not in encoded
    assert "stable_identifier" not in encoded
    assert "secret_key" not in encoded
    assert "raw_biosignal" not in encoded

