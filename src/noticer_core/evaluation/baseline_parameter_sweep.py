"""Fail-closed parameter sweep and multi-axis reporting for K7 baselines."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    ComparisonManifest,
    manifest_digest,
    validate_manifest,
)

FORMAT_VERSION = "noticer.k7.baseline-parameter-sweep.v1"
SELECTION_ORDER = ("failure", "attack", "latency", "bandwidth", "state")


class ParameterSweepError(ValueError):
    """A reproducibility or fairness invariant was violated."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class AxisMetrics:
    """Raw, non-aggregated measurements; lower is better on every axis."""

    attack_success_rate: float
    bandwidth_bytes: int
    failure_count: int
    latency_slots: float
    state_units: int


@dataclass(frozen=True)
class CandidateObservation:
    mechanism_id: str
    config_sha256: str
    split: str
    privacy_notion: str
    metrics: AxisMetrics


@dataclass(frozen=True)
class SelectedCandidate:
    mechanism_id: str
    config_sha256: str


@dataclass(frozen=True)
class PrivacyNotionSection:
    privacy_notion: str
    mechanism_ids: tuple[str, ...]


@dataclass(frozen=True)
class SweepReport:
    format_version: str
    manifest_sha256: str
    selection_split: str
    evaluation_split: str
    selection_order: tuple[str, ...]
    report_axes: tuple[str, ...]
    observations: tuple[CandidateObservation, ...]
    selected_candidates: tuple[SelectedCandidate, ...]
    privacy_notion_sections: tuple[PrivacyNotionSection, ...]
    metrics_are_not_aggregated: bool
    security_proof: bool


def build_sweep_report(
    manifest: ComparisonManifest,
    observations: tuple[CandidateObservation, ...],
) -> SweepReport:
    """Validate complete coverage and reproduce every precommitted selection."""

    validate_manifest(manifest)
    mechanisms = {item.mechanism_id: item for item in manifest.mechanisms}
    expected = {
        (mechanism.mechanism_id, config, split)
        for mechanism in manifest.mechanisms
        for config in mechanism.candidate_config_sha256
        for split in (manifest.shared.selection_split, manifest.shared.evaluation_split)
    }
    actual: set[tuple[str, str, str]] = set()
    by_key: dict[tuple[str, str, str], CandidateObservation] = {}
    for observation in observations:
        _validate_observation(observation)
        mechanism = mechanisms.get(observation.mechanism_id)
        if mechanism is None or observation.config_sha256 not in mechanism.candidate_config_sha256:
            raise ParameterSweepError("undeclared_candidate")
        if observation.privacy_notion != mechanism.privacy_notion:
            raise ParameterSweepError("privacy_notion_mismatch")
        key = (observation.mechanism_id, observation.config_sha256, observation.split)
        if key in actual:
            raise ParameterSweepError("duplicate_observation")
        actual.add(key)
        by_key[key] = observation
    if actual != expected:
        raise ParameterSweepError("incomplete_candidate_coverage")

    selected: list[SelectedCandidate] = []
    for mechanism in manifest.mechanisms:
        development = [
            by_key[(mechanism.mechanism_id, config, manifest.shared.selection_split)]
            for config in mechanism.candidate_config_sha256
        ]
        winner = min(development, key=_selection_key)
        if winner.config_sha256 != mechanism.selected_config_sha256:
            raise ParameterSweepError("precommitted_selection_mismatch")
        selected.append(SelectedCandidate(mechanism.mechanism_id, winner.config_sha256))

    notions: dict[str, list[str]] = {}
    for mechanism in manifest.mechanisms:
        notions.setdefault(mechanism.privacy_notion, []).append(mechanism.mechanism_id)
    notion_sections = tuple(
        PrivacyNotionSection(notion, tuple(sorted(mechanism_ids)))
        for notion, mechanism_ids in sorted(notions.items())
    )
    ordered_observations = tuple(
        sorted(
            observations,
            key=lambda item: (item.mechanism_id, item.config_sha256, item.split),
        )
    )
    return SweepReport(
        FORMAT_VERSION,
        manifest_digest(manifest),
        manifest.shared.selection_split,
        manifest.shared.evaluation_split,
        SELECTION_ORDER,
        AXES,
        ordered_observations,
        tuple(selected),
        notion_sections,
        True,
        False,
    )


def canonical_report_json(report: SweepReport) -> str:
    """Serialize one report into stable UTF-8 JSON text."""

    if (
        report.format_version != FORMAT_VERSION
        or report.selection_order != SELECTION_ORDER
        or report.report_axes != AXES
        or not report.metrics_are_not_aggregated
        or report.security_proof
    ):
        raise ParameterSweepError("invalid_report_header")
    return json.dumps(asdict(report), sort_keys=True, separators=(",", ":"))


def report_digest(report: SweepReport) -> str:
    return hashlib.sha256(canonical_report_json(report).encode("utf-8")).hexdigest()


def write_report(report: SweepReport, destination: Path) -> None:
    """Write a canonical artifact without depending on the process working directory."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_report_json(report) + "\n", encoding="utf-8")


def _validate_observation(observation: CandidateObservation) -> None:
    metrics = observation.metrics
    numeric = (
        metrics.attack_success_rate,
        metrics.bandwidth_bytes,
        metrics.failure_count,
        metrics.latency_slots,
        metrics.state_units,
    )
    if (
        not observation.mechanism_id
        or len(observation.config_sha256) != 64
        or any(character not in "0123456789abcdef" for character in observation.config_sha256)
        or not observation.split
        or not observation.privacy_notion
        or any(
            isinstance(value, bool) or not math.isfinite(value) or value < 0
            for value in numeric
        )
        or metrics.attack_success_rate > 1
        or type(metrics.bandwidth_bytes) is not int
        or type(metrics.failure_count) is not int
        or type(metrics.state_units) is not int
    ):
        raise ParameterSweepError("invalid_observation")


def _selection_key(observation: CandidateObservation) -> tuple[float | int | str, ...]:
    metrics = observation.metrics
    return (
        metrics.failure_count,
        metrics.attack_success_rate,
        metrics.latency_slots,
        metrics.bandwidth_bytes,
        metrics.state_units,
        observation.config_sha256,
    )
