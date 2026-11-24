from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from noticer_core.data.contracts import WindowDataset
from noticer_core.data.k20_positive_control import (
    PositiveControlConfig,
    generate_positive_control,
)
from noticer_core.evaluation.k20_identity_contract import WindowIdentity
from noticer_core.evaluation.k20_provenance import (
    build_provenance_receipt,
    dataset_digest,
)
from noticer_core.evaluation.k20_session_split import (
    SessionAssignment,
    SplitName,
    verify_session_disjoint_split,
)


def inputs() -> tuple[WindowDataset, object]:
    dataset = generate_positive_control(
        PositiveControlConfig(subjects=3, windows_per_session=3), seed=9
    )
    rows = [
        WindowIdentity(str(subject), str(session), f"window_{index:05d}", int(time))
        for index, (subject, session, time) in enumerate(
            zip(dataset.subject_ids, dataset.session_ids, dataset.time_indices, strict=True)
        )
    ]
    names = (SplitName.TRAIN, SplitName.VALIDATION, SplitName.TEST)
    assignments = [
        SessionAssignment(str(session), names[index % 3])
        for index, session in enumerate(np.unique(dataset.session_ids))
    ]
    return dataset, verify_session_disjoint_split(rows, assignments)


def test_receipt_is_deterministic_and_binds_every_input() -> None:
    dataset, split = inputs()
    first = build_provenance_receipt(
        dataset,
        split,
        manifest_sha256="a" * 64,
        implementation_revision="commit-123",
        seeds=(1, 2, 3),
    )
    second = build_provenance_receipt(
        dataset,
        split,
        manifest_sha256="a" * 64,
        implementation_revision="commit-123",
        seeds=(1, 2, 3),
    )
    assert first == second
    assert len(first.run_sha256) == 64
    assert replace(first, seeds=(1, 2, 4)) != first


def test_single_feature_change_and_row_order_change_digest() -> None:
    dataset, _ = inputs()
    changed_features = dataset.features.copy()
    changed_features[0, 0] += 1e-12
    changed = replace(dataset, features=changed_features)
    assert dataset_digest(changed) != dataset_digest(dataset)

    order = np.arange(dataset.n_windows)[::-1]
    reordered = WindowDataset(
        features=dataset.features[order],
        subject_ids=dataset.subject_ids[order],
        session_ids=dataset.session_ids[order],
        condition_ids=dataset.condition_ids[order],
        time_indices=dataset.time_indices[order],
        feature_names=dataset.feature_names,
    )
    assert dataset_digest(reordered) != dataset_digest(dataset)


@pytest.mark.parametrize("digest", ["A" * 64, "0" * 63, "z" * 64])
def test_noncanonical_manifest_digest_is_rejected(digest: str) -> None:
    dataset, split = inputs()
    with pytest.raises(ValueError, match="SHA-256"):
        build_provenance_receipt(
            dataset,
            split,
            manifest_sha256=digest,
            implementation_revision="commit-123",
            seeds=(1,),
        )
