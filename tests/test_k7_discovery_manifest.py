from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from noticer_core.evaluation.discovery_manifest import (
    MANIFEST_FIELDS,
    CheckerStatus,
    DiscoveryClass,
    DiscoveryManifestError,
    DiscoveryObservation,
    ExpectedStatus,
    ResourceReason,
    SynthesisStatus,
    TemplateRelation,
    build_discovery_manifest,
    load_discovery_gate,
    write_discovery_manifest,
)
from noticer_core.evaluation.heldout_ledger import (
    open_held_out,
    seal_precommit,
    validate_receipt_chain,
)

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "configs" / "quotient_forge" / "discovery_gate_v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "k7_discovery_manifest_v1.schema.json"


def _observations(gate: object) -> dict[str, DiscoveryObservation]:
    result = {}
    for index, case in enumerate(gate.cases):
        if case.expected_status is ExpectedStatus.REALIZABLE:
            observation = DiscoveryObservation(
                family_id=case.family_id,
                synthesis_status=SynthesisStatus.REALIZABLE,
                checker_status=CheckerStatus.VERIFIED,
                canonical_machine_sha256=f"{index + 1:064x}",
                template_relation=TemplateRelation.ABSENT,
                template_machine_sha256=None,
                equivalence_evidence_sha256=None,
                resource_reason=None,
            )
        else:
            observation = DiscoveryObservation(
                family_id=case.family_id,
                synthesis_status=SynthesisStatus(case.expected_status.value),
                checker_status=CheckerStatus.NOT_RUN,
                canonical_machine_sha256=None,
                template_relation=TemplateRelation.ABSENT,
                template_machine_sha256=None,
                equivalence_evidence_sha256=None,
                resource_reason=None,
            )
        result[case.family_id] = observation
    return result


def test_checker_valid_untemplated_held_out_discovery_passes_gate() -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    sealed = seal_precommit(gate.precommit)
    manifest = build_discovery_manifest(gate, sealed, _observations(gate))
    assert manifest["gate_status"] == "PASS"
    assert manifest["summary"]["held_out_case_count"] == 8
    assert manifest["summary"]["valid_non_equivalent_count"] >= 1
    assert manifest["summary"]["expected_nonrealizable_count"] == 3
    assert len(manifest["checker_sha256"]) == 64
    assert len(manifest["equivalence_checker_sha256"]) == 64


def test_absent_template_never_bypasses_checker_validity() -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    observations = _observations(gate)
    target = next(case for case in gate.cases if case.expected_status is ExpectedStatus.REALIZABLE)
    observations[target.family_id] = replace(
        observations[target.family_id], checker_status=CheckerStatus.NOT_RUN
    )
    manifest = build_discovery_manifest(gate, seal_precommit(gate.precommit), observations)
    row = next(row for row in manifest["cases"] if row["family_id"] == target.family_id)
    assert row["classification"] == DiscoveryClass.INVALID_DISCOVERY.value
    assert manifest["gate_status"] == "FAIL"


def test_equivalent_author_template_is_not_counted_as_novel() -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    target = next(case for case in gate.cases if case.expected_status is ExpectedStatus.REALIZABLE)
    template_digest = "c" * 64
    cases = tuple(
        replace(case, author_template_sha256=template_digest)
        if case.family_id == target.family_id
        else case
        for case in gate.cases
    )
    strict_gate = replace(
        gate,
        cases=cases,
        minimum_held_out_valid_non_equivalent=5,
    )
    observations = _observations(gate)
    observations[target.family_id] = replace(
        observations[target.family_id],
        template_relation=TemplateRelation.EQUIVALENT,
        template_machine_sha256=template_digest,
        equivalence_evidence_sha256="d" * 64,
    )
    manifest = build_discovery_manifest(
        strict_gate,
        seal_precommit(strict_gate.precommit),
        observations,
    )
    assert manifest["summary"]["valid_equivalent_count"] == 1
    assert manifest["summary"]["valid_non_equivalent_count"] == 4
    assert manifest["gate_status"] == "FAIL"


def test_inconclusive_and_status_disagreement_are_blocked_not_negative() -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    target = next(case for case in gate.cases if case.expected_status is ExpectedStatus.REALIZABLE)
    observations = _observations(gate)
    observations[target.family_id] = replace(
        observations[target.family_id],
        synthesis_status=SynthesisStatus.INCONCLUSIVE,
        checker_status=CheckerStatus.INCONCLUSIVE,
        canonical_machine_sha256=None,
        template_relation=TemplateRelation.INCONCLUSIVE,
        resource_reason=ResourceReason.TIME_LIMIT,
    )
    manifest = build_discovery_manifest(gate, seal_precommit(gate.precommit), observations)
    assert manifest["gate_status"] == "BLOCKED"
    assert manifest["summary"]["inconclusive_count"] == 1
    assert manifest["summary"]["expected_nonrealizable_count"] == 3

    observations = _observations(gate)
    observations[target.family_id] = replace(
        observations[target.family_id],
        synthesis_status=SynthesisStatus.UNSAT_AT_BOUND,
        checker_status=CheckerStatus.NOT_RUN,
        canonical_machine_sha256=None,
    )
    manifest = build_discovery_manifest(gate, seal_precommit(gate.precommit), observations)
    assert manifest["gate_status"] == "BLOCKED"
    assert manifest["summary"]["status_disagreement_count"] == 1


def test_manifest_is_canonical_private_free_and_opens_the_ledger(tmp_path: Path) -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    sealed = seal_precommit(gate.precommit)
    manifest = build_discovery_manifest(gate, sealed, _observations(gate))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["properties"]) == MANIFEST_FIELDS
    output = tmp_path / "discovery.json"
    write_discovery_manifest(output, manifest)
    original = output.read_bytes()
    write_discovery_manifest(output, manifest)
    assert output.read_bytes() == original
    opened = open_held_out(
        gate.precommit,
        sealed,
        original,
        result_format="noticer.k7.discovery-result.v1",
    )
    validate_receipt_chain(gate.precommit, (sealed, opened))
    assert opened.result is not None
    assert opened.result.byte_count == len(original)
    assert b"participant_id" not in original


def test_gate_rejects_non_held_out_or_missing_observations() -> None:
    gate = load_discovery_gate(GATE_PATH, repository_root=ROOT)
    observations = _observations(gate)
    observations.pop(next(iter(observations)))
    with pytest.raises(DiscoveryManifestError, match="exactly cover"):
        build_discovery_manifest(
            gate,
            seal_precommit(gate.precommit),
            observations,
        )
