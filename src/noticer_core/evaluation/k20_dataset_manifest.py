"""Canonical dataset manifest contract for K20 QuotientEvidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "noticer.k20.dataset-manifest.v1"
_HEX_DIGEST_LENGTH = 64


class DatasetManifestError(ValueError):
    """Raised when a K20 dataset manifest violates the frozen contract."""


class EvidenceClass(StrEnum):
    FIXTURE = "fixture"
    SYNTHETIC_CONTROL = "synthetic-control"
    PILOT = "pilot"
    REGISTERED_EXPERIMENT = "registered-experiment"
    EXTERNAL_REPLICATION = "external-replication"

    @property
    def permits_scientific_claim(self) -> bool:
        return self in {
            EvidenceClass.REGISTERED_EXPERIMENT,
            EvidenceClass.EXTERNAL_REPLICATION,
        }


@dataclass(frozen=True, slots=True)
class DatasetManifest:
    """Privacy-preserving metadata required to identify an evaluation dataset."""

    dataset_id: str
    evidence_class: EvidenceClass
    source_sha256: str
    feature_schema_sha256: str
    subject_count: int
    session_count: int
    window_count: int
    license_id: str
    redistributable: bool
    contains_raw_biosignal: bool
    registered_protocol_id: str | None = None
    schema: str = MANIFEST_SCHEMA

    def validate(self) -> None:
        if self.schema != MANIFEST_SCHEMA:
            raise DatasetManifestError("unsupported dataset manifest schema")
        if not self.dataset_id or not self.dataset_id.isascii():
            raise DatasetManifestError("dataset_id must be non-empty ASCII")
        if any(token in self.dataset_id.lower() for token in ("subject", "email", "name=")):
            raise DatasetManifestError("dataset_id must not encode a participant identifier")
        _require_digest("source_sha256", self.source_sha256)
        _require_digest("feature_schema_sha256", self.feature_schema_sha256)
        if min(self.subject_count, self.session_count, self.window_count) < 1:
            raise DatasetManifestError("dataset counts must be positive")
        if self.session_count < self.subject_count:
            raise DatasetManifestError("session_count must be at least subject_count")
        if self.window_count < self.session_count:
            raise DatasetManifestError("window_count must be at least session_count")
        if not self.license_id.strip():
            raise DatasetManifestError("license_id is required")
        if self.evidence_class.permits_scientific_claim and not self.registered_protocol_id:
            raise DatasetManifestError("claim-eligible data requires registered_protocol_id")
        if self.evidence_class in {EvidenceClass.FIXTURE, EvidenceClass.SYNTHETIC_CONTROL}:
            if self.registered_protocol_id is not None:
                raise DatasetManifestError("test data cannot be promoted by a protocol identifier")

    @property
    def permits_scientific_claim(self) -> bool:
        self.validate()
        return self.evidence_class.permits_scientific_claim

    def canonical_bytes(self) -> bytes:
        self.validate()
        value = asdict(self)
        value["evidence_class"] = self.evidence_class.value
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def load_dataset_manifest(path: Path) -> DatasetManifest:
    """Load an exact-field JSON manifest and validate it fail-closed."""
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DatasetManifestError("cannot read canonical UTF-8 manifest") from error
    if not isinstance(value, dict):
        raise DatasetManifestError("dataset manifest root must be an object")
    expected = {field.name for field in DatasetManifest.__dataclass_fields__.values()}
    if set(value) != expected:
        raise DatasetManifestError("dataset manifest fields mismatch")
    try:
        value["evidence_class"] = EvidenceClass(value["evidence_class"])
        manifest = DatasetManifest(**value)
    except (TypeError, ValueError) as error:
        raise DatasetManifestError("dataset manifest field has an invalid type") from error
    manifest.validate()
    if path.read_bytes() != manifest.canonical_bytes():
        raise DatasetManifestError("dataset manifest is not canonical")
    return manifest


def write_dataset_manifest(path: Path, manifest: DatasetManifest) -> None:
    """Write canonical UTF-8 without creating participant-derived filenames."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(manifest.canonical_bytes())


def _require_digest(name: str, value: str) -> None:
    if len(value) != _HEX_DIGEST_LENGTH:
        raise DatasetManifestError(f"{name} must be a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as error:
        raise DatasetManifestError(f"{name} must be lowercase hexadecimal") from error
    if value != value.lower():
        raise DatasetManifestError(f"{name} must be lowercase hexadecimal")

