"""Domain-separated input provenance digests for K20 experiments."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from struct import pack

import numpy as np

from noticer_core.data.contracts import WindowDataset
from noticer_core.evaluation.k20_session_split import VerifiedSessionSplit

_DATASET_DOMAIN = b"NOTICER_K20_DATASET_V1\x00"
_SPLIT_DOMAIN = b"NOTICER_K20_SPLIT_V1\x00"
_RUN_DOMAIN = b"NOTICER_K20_RUN_V1\x00"


@dataclass(frozen=True, slots=True)
class ProvenanceReceipt:
    dataset_sha256: str
    split_sha256: str
    manifest_sha256: str
    implementation_revision: str
    seeds: tuple[int, ...]
    run_sha256: str


def dataset_digest(dataset: WindowDataset) -> str:
    """Bind all ordered feature and metadata values into one digest."""
    digest = hashlib.sha256(_DATASET_DOMAIN)
    features = np.ascontiguousarray(dataset.features, dtype="<f8")
    digest.update(pack(">QQ", dataset.n_windows, dataset.n_features))
    digest.update(features.tobytes(order="C"))
    for name in dataset.feature_names:
        _update_text(digest, name)
    for values in (
        dataset.subject_ids,
        dataset.session_ids,
        dataset.condition_ids,
        dataset.time_indices,
    ):
        for value in values:
            _update_text(digest, str(value))
    return digest.hexdigest()


def split_digest(split: VerifiedSessionSplit) -> str:
    digest = hashlib.sha256(_SPLIT_DOMAIN)
    for assignment in split.assignments:
        _update_text(digest, assignment.session_id)
        _update_text(digest, assignment.split.value)
    return digest.hexdigest()


def build_provenance_receipt(
    dataset: WindowDataset,
    split: VerifiedSessionSplit,
    *,
    manifest_sha256: str,
    implementation_revision: str,
    seeds: Iterable[int],
) -> ProvenanceReceipt:
    """Build a stable run identity without embedding participant metadata."""
    _require_sha256(manifest_sha256)
    if not implementation_revision or not implementation_revision.isascii():
        raise ValueError("implementation_revision must be non-empty ASCII")
    seed_values = tuple(seeds)
    if not seed_values or any(seed < 0 or seed >= 2**64 for seed in seed_values):
        raise ValueError("seeds must contain unsigned 64-bit integers")
    dataset_sha256 = dataset_digest(dataset)
    split_sha256 = split_digest(split)
    payload = json.dumps(
        {
            "dataset_sha256": dataset_sha256,
            "implementation_revision": implementation_revision,
            "manifest_sha256": manifest_sha256,
            "seeds": seed_values,
            "split_sha256": split_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    run_sha256 = hashlib.sha256(_RUN_DOMAIN + payload).hexdigest()
    return ProvenanceReceipt(
        dataset_sha256,
        split_sha256,
        manifest_sha256,
        implementation_revision,
        seed_values,
        run_sha256,
    )


def _update_text(digest: object, value: str) -> None:
    encoded = value.encode("utf-8")
    digest.update(pack(">Q", len(encoded)))
    digest.update(encoded)


def _require_sha256(value: str) -> None:
    if len(value) != 64 or value != value.lower():
        raise ValueError("manifest_sha256 must be lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError("manifest_sha256 must be lowercase SHA-256") from error

