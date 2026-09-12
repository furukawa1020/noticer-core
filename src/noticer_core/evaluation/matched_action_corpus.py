"""Fail-closed corpus contract for implementation-derived matched-action traces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

RUNTIME_CAPTURE_SOURCE = "rust_runtime_capture_v1"


class CorpusContractError(ValueError):
    """Raised when a corpus or split violates the pre-registered contract."""


class Split(StrEnum):
    TRAIN = "train"
    DEVELOPMENT = "development"
    TEST = "test"


@dataclass(frozen=True)
class MatchedActionTraceRow:
    pair_id: str
    family_id: str
    session_id: str
    side: str
    action_semantics_sha256: str
    runtime_capture_sha256: str
    schedule_variant: str
    fault_variant: str
    source: str = RUNTIME_CAPTURE_SOURCE


@dataclass(frozen=True)
class SplitPolicy:
    family_split: Mapping[str, Split]
    heldout_schedule_variants: frozenset[str]
    heldout_fault_variants: frozenset[str]


def split_matched_action_corpus(
    rows: Iterable[MatchedActionTraceRow],
    policy: SplitPolicy,
) -> dict[Split, tuple[MatchedActionTraceRow, ...]]:
    """Validate and split without row/window-level randomization."""
    materialized = tuple(rows)
    if not materialized:
        raise CorpusContractError("corpus is empty")
    by_pair: dict[str, list[MatchedActionTraceRow]] = defaultdict(list)
    result: dict[Split, list[MatchedActionTraceRow]] = {
        split: [] for split in Split
    }
    family_seen: dict[str, Split] = {}
    session_seen: dict[str, Split] = {}

    for row in materialized:
        _validate_row(row)
        split = policy.family_split.get(row.family_id)
        if split is None:
            raise CorpusContractError(f"family has no pre-registered split: {row.family_id}")
        if row.schedule_variant in policy.heldout_schedule_variants and split is not Split.TEST:
            raise CorpusContractError("held-out schedule variant escaped into calibration data")
        if row.fault_variant in policy.heldout_fault_variants and split is not Split.TEST:
            raise CorpusContractError("held-out fault variant escaped into calibration data")
        if family_seen.setdefault(row.family_id, split) is not split:
            raise CorpusContractError("family crosses split boundaries")
        if session_seen.setdefault(row.session_id, split) is not split:
            raise CorpusContractError("session crosses split boundaries")
        by_pair[row.pair_id].append(row)
        result[split].append(row)

    pair_seen: dict[str, Split] = {}
    for pair_id, pair_rows in by_pair.items():
        _validate_pair(pair_id, pair_rows)
        pair_split = policy.family_split[pair_rows[0].family_id]
        if pair_seen.setdefault(pair_id, pair_split) is not pair_split:
            raise CorpusContractError("pair crosses split boundaries")

    if not all(result.values()):
        raise CorpusContractError("train, development, and test must all be non-empty")
    observed_test_schedules = {
        row.schedule_variant for row in result[Split.TEST]
    }
    observed_test_faults = {row.fault_variant for row in result[Split.TEST]}
    if not policy.heldout_schedule_variants <= observed_test_schedules:
        raise CorpusContractError("test split misses a held-out schedule variant")
    if not policy.heldout_fault_variants <= observed_test_faults:
        raise CorpusContractError("test split misses a held-out fault variant")
    return {split: tuple(values) for split, values in result.items()}


def _validate_row(row: MatchedActionTraceRow) -> None:
    if row.source != RUNTIME_CAPTURE_SOURCE:
        raise CorpusContractError("non-runtime or synthetic-copy source is forbidden")
    if row.side not in {"left", "right"}:
        raise CorpusContractError(f"invalid pair side: {row.side}")
    for name, digest in (
        ("action_semantics_sha256", row.action_semantics_sha256),
        ("runtime_capture_sha256", row.runtime_capture_sha256),
    ):
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise CorpusContractError(f"invalid {name}")
    if not all(
        (
            row.pair_id,
            row.family_id,
            row.session_id,
            row.schedule_variant,
            row.fault_variant,
        )
    ):
        raise CorpusContractError("corpus identifiers must be non-empty")


def _validate_pair(pair_id: str, rows: list[MatchedActionTraceRow]) -> None:
    if len(rows) != 2 or {row.side for row in rows} != {"left", "right"}:
        raise CorpusContractError(f"pair must contain one left and one right row: {pair_id}")
    if len({row.family_id for row in rows}) != 1:
        raise CorpusContractError(f"pair family mismatch: {pair_id}")
    if len({row.action_semantics_sha256 for row in rows}) != 1:
        raise CorpusContractError(f"pair is not action-matched: {pair_id}")
    if len({row.session_id for row in rows}) != 2:
        raise CorpusContractError(f"private-distinct sessions required: {pair_id}")
