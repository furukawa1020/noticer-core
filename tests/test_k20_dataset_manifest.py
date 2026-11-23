from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from noticer_core.evaluation.k20_dataset_manifest import (
    DatasetManifest,
    DatasetManifestError,
    EvidenceClass,
    load_dataset_manifest,
    write_dataset_manifest,
)


def manifest(**changes: object) -> DatasetManifest:
    value = DatasetManifest(
        dataset_id="wesad-derived-v1",
        evidence_class=EvidenceClass.REGISTERED_EXPERIMENT,
        source_sha256="1" * 64,
        feature_schema_sha256="2" * 64,
        subject_count=15,
        session_count=45,
        window_count=4500,
        license_id="custom-research-license",
        redistributable=False,
        contains_raw_biosignal=False,
        registered_protocol_id="K20-PROTOCOL-V1",
    )
    return replace(value, **changes)


def test_manifest_round_trip_is_canonical_and_digest_stable(tmp_path: Path) -> None:
    path = tmp_path / "dataset.json"
    value = manifest()
    write_dataset_manifest(path, value)

    loaded = load_dataset_manifest(path)

    assert loaded == value
    assert loaded.manifest_sha256 == value.manifest_sha256
    assert path.read_text(encoding="utf-8").startswith('{"contains_raw_biosignal"')


def test_fixture_cannot_be_promoted_to_scientific_evidence() -> None:
    fixture = manifest(
        evidence_class=EvidenceClass.FIXTURE,
        registered_protocol_id=None,
    )
    assert fixture.permits_scientific_claim is False

    with pytest.raises(DatasetManifestError, match="cannot be promoted"):
        replace(fixture, registered_protocol_id="AFTER-THE-FACT").validate()


def test_claim_eligible_data_requires_preregistration() -> None:
    with pytest.raises(DatasetManifestError, match="registered_protocol_id"):
        manifest(registered_protocol_id=None).validate()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"source_sha256": "not-a-digest"}, "SHA-256"),
        ({"subject_count": 0}, "positive"),
        ({"session_count": 10}, "at least subject_count"),
        ({"window_count": 20}, "at least session_count"),
        ({"dataset_id": "subject_001"}, "participant identifier"),
    ],
)
def test_invalid_metadata_fails_closed(change: dict[str, object], message: str) -> None:
    with pytest.raises(DatasetManifestError, match=message):
        manifest(**change).validate()


def test_unknown_fields_and_noncanonical_json_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "dataset.json"
    value = json.loads(manifest().canonical_bytes())
    value["participant_name"] = "forbidden"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(DatasetManifestError, match="fields mismatch"):
        load_dataset_manifest(path)

    value.pop("participant_name")
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(DatasetManifestError, match="not canonical"):
        load_dataset_manifest(path)
