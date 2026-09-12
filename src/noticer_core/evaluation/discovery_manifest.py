"""Checker-gated K7 discovery manifest with canonical template relations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from noticer_core.evaluation.benchmark_calibration import (
    CalibrationScope,
    ExpectedStatus,
    ResourceReason,
    load_calibration_lock,
)
from noticer_core.evaluation.benchmark_case import load_benchmark_case
from noticer_core.evaluation.heldout_ledger import (
    HeldOutPrecommit,
    LedgerState,
    OpeningReceipt,
    load_precommit,
    load_receipts,
    receipt_sha256,
    validate_receipt_chain,
)

GATE_SCHEMA: Final = "noticer.k7.discovery-gate.v1"
OBSERVATION_SCHEMA: Final = "noticer.k7.discovery-observations.v1"
MANIFEST_SCHEMA: Final = "noticer.k7.discovery-result.v1"
EQUIVALENCE_SOURCE_PATH: Final = "crates/quotient-forge-synth/src/machine_equivalence.rs"
GATE_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "state",
        "precommit_path",
        "equivalence_checker_path",
        "equivalence_checker_sha256",
        "minimum_held_out_valid_non_equivalent",
        "policies",
    }
)
POLICY_FIELDS: Final = frozenset(
    {
        "checker_verification_required",
        "absent_template_is_automatic_novel",
        "equivalent_template_counts_as_novel",
        "inconclusive_counts_as_negative",
        "deployment_generalization_allowed",
    }
)
OBSERVATION_FIELDS: Final = frozenset(
    {
        "family_id",
        "synthesis_status",
        "checker_status",
        "canonical_machine_sha256",
        "template_relation",
        "template_machine_sha256",
        "equivalence_evidence_sha256",
        "resource_reason",
    }
)
MANIFEST_FIELDS: Final = frozenset(
    {
        "schema",
        "gate_status",
        "bindings",
        "checker_sha256",
        "equivalence_checker_sha256",
        "seal_receipt_sha256",
        "minimum_held_out_valid_non_equivalent",
        "summary",
        "cases",
        "private_field_count",
    }
)
_EXPECTED_POLICIES: Final = {
    "checker_verification_required": True,
    "absent_template_is_automatic_novel": False,
    "equivalent_template_counts_as_novel": False,
    "inconclusive_counts_as_negative": False,
    "deployment_generalization_allowed": False,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DiscoveryManifestError(ValueError):
    """A gate, observation, equivalence claim, or manifest was invalid."""


class SynthesisStatus(StrEnum):
    """Discovery outcomes without collapsing bounded and invalid cases."""

    REALIZABLE = "REALIZABLE"
    UNSAT_AT_BOUND = "UNSAT_AT_BOUND"
    INVALID_SPEC = "INVALID_SPEC"
    INCONCLUSIVE = "INCONCLUSIVE"


class CheckerStatus(StrEnum):
    """Independent checker status for a discovered machine."""

    VERIFIED = "VERIFIED"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"


class TemplateRelation(StrEnum):
    """Canonical relation after state renaming and dead-state removal."""

    EQUIVALENT = "EQUIVALENT"
    DISTINCT = "DISTINCT"
    ABSENT = "ABSENT"
    INCONCLUSIVE = "INCONCLUSIVE"


class DiscoveryClass(StrEnum):
    """Gate classification that keeps validity, novelty, and limits separate."""

    VALID_EQUIVALENT = "VALID_EQUIVALENT"
    VALID_NON_EQUIVALENT = "VALID_NON_EQUIVALENT"
    VALID_UNTEMPLATED = "VALID_UNTEMPLATED"
    EXPECTED_NONREALIZABLE = "EXPECTED_NONREALIZABLE"
    INVALID_DISCOVERY = "INVALID_DISCOVERY"
    STATUS_DISAGREEMENT = "STATUS_DISAGREEMENT"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class GatePolicies:
    """Frozen admission policy for K7 discovery claims."""

    checker_verification_required: bool
    absent_template_is_automatic_novel: bool
    equivalent_template_counts_as_novel: bool
    inconclusive_counts_as_negative: bool
    deployment_generalization_allowed: bool


@dataclass(frozen=True, slots=True)
class GateCase:
    """Held-out case metadata loaded from digest-bound case contracts."""

    family_id: str
    expected_status: ExpectedStatus
    author_template_sha256: str | None


@dataclass(frozen=True, slots=True)
class DiscoveryGate:
    """Frozen checker and novelty gate bound to one precommit."""

    precommit: HeldOutPrecommit
    equivalence_checker_sha256: str
    minimum_held_out_valid_non_equivalent: int
    policies: GatePolicies
    cases: tuple[GateCase, ...]


@dataclass(frozen=True, slots=True)
class DiscoveryObservation:
    """One held-out synthesis/checker/equivalence observation."""

    family_id: str
    synthesis_status: SynthesisStatus
    checker_status: CheckerStatus
    canonical_machine_sha256: str | None
    template_relation: TemplateRelation
    template_machine_sha256: str | None
    equivalence_evidence_sha256: str | None
    resource_reason: ResourceReason | None


def load_discovery_gate(path: Path, *, repository_root: Path | None = None) -> DiscoveryGate:
    """Load a gate and verify precommit, checker, and held-out case bindings."""

    root = repository_root or path.resolve().parents[2]
    document = _load_yaml_mapping(path)
    _require_fields(document, GATE_FIELDS, "gate")
    if document["schema"] != GATE_SCHEMA or document["version"] != 1:
        raise DiscoveryManifestError("unsupported discovery gate schema")
    if document["state"] != "FROZEN":
        raise DiscoveryManifestError("discovery gate must be FROZEN")
    precommit_path = _fixed_path(
        document["precommit_path"],
        "configs/quotient_forge/heldout_precommit_v1.yaml",
    )
    equivalence_path = _fixed_path(document["equivalence_checker_path"], EQUIVALENCE_SOURCE_PATH)
    expected_equivalence_digest = _normalized_file_sha256(root / equivalence_path)
    if document["equivalence_checker_sha256"] != expected_equivalence_digest:
        raise DiscoveryManifestError("equivalence checker digest is stale")
    minimum = _positive_integer(
        document["minimum_held_out_valid_non_equivalent"],
        "minimum_held_out_valid_non_equivalent",
    )
    policies_raw = _mapping(document["policies"], "policies")
    _require_fields(policies_raw, POLICY_FIELDS, "policies")
    if policies_raw != _EXPECTED_POLICIES:
        raise DiscoveryManifestError("discovery policies differ from the frozen gate")

    precommit = load_precommit(root / precommit_path, repository_root=root)
    lock = load_calibration_lock(root / precommit.calibration_lock_path, repository_root=root)
    cases = []
    for calibration_case in lock.cases:
        if calibration_case.calibration_scope is not CalibrationScope.SEALED_HELD_OUT:
            continue
        category = calibration_case.family_id.split("_", 1)[0]
        case = load_benchmark_case(
            root / lock.case_root / category / f"{calibration_case.family_id}.yaml"
        )
        cases.append(
            GateCase(
                family_id=calibration_case.family_id,
                expected_status=calibration_case.expected_status,
                author_template_sha256=case.author_template_sha256,
            )
        )
    if tuple(case.family_id for case in cases) != precommit.held_out_families:
        raise DiscoveryManifestError("gate cases differ from precommitted held-out split")
    if minimum > len(cases):
        raise DiscoveryManifestError("minimum discovery count exceeds held-out corpus")
    return DiscoveryGate(
        precommit=precommit,
        equivalence_checker_sha256=expected_equivalence_digest,
        minimum_held_out_valid_non_equivalent=minimum,
        policies=GatePolicies(**policies_raw),
        cases=tuple(cases),
    )


def load_discovery_observations(path: Path) -> dict[str, DiscoveryObservation]:
    """Load exact held-out observations without accepting local paths or raw machines."""

    document = _load_yaml_mapping(path)
    _require_fields(document, frozenset({"schema", "cases"}), "observations")
    if document["schema"] != OBSERVATION_SCHEMA:
        raise DiscoveryManifestError("unsupported discovery observation schema")
    rows = document["cases"]
    if type(rows) is not list:
        raise DiscoveryManifestError("observations.cases must be a list")
    result: dict[str, DiscoveryObservation] = {}
    for index, raw in enumerate(rows):
        observation = _parse_observation(raw, index)
        if observation.family_id in result:
            raise DiscoveryManifestError(
                f"duplicate discovery observation: {observation.family_id}"
            )
        result[observation.family_id] = observation
    return result


def build_discovery_manifest(
    gate: DiscoveryGate,
    sealed_receipt: OpeningReceipt,
    observations: Mapping[str, DiscoveryObservation],
) -> dict[str, object]:
    """Aggregate held-out discovery only after seal and checker validation."""

    validate_receipt_chain(gate.precommit, (sealed_receipt,))
    if sealed_receipt.to_state is not LedgerState.SEALED:
        raise DiscoveryManifestError("discovery requires a SEALED receipt")
    expected_ids = {case.family_id for case in gate.cases}
    if set(observations) != expected_ids:
        raise DiscoveryManifestError("observations must exactly cover held-out cases")

    rows = []
    classes: Counter[str] = Counter()
    for case in gate.cases:
        observation = observations[case.family_id]
        classification = _classify(case, observation)
        classes[classification.value] += 1
        rows.append(_observation_mapping(case, observation, classification))
    qualifying = (
        classes[DiscoveryClass.VALID_NON_EQUIVALENT.value]
        + classes[DiscoveryClass.VALID_UNTEMPLATED.value]
    )
    blocked = (
        classes[DiscoveryClass.STATUS_DISAGREEMENT.value]
        + classes[DiscoveryClass.INCONCLUSIVE.value]
    )
    invalid = classes[DiscoveryClass.INVALID_DISCOVERY.value]
    if blocked:
        gate_status = "BLOCKED"
    elif invalid or qualifying < gate.minimum_held_out_valid_non_equivalent:
        gate_status = "FAIL"
    else:
        gate_status = "PASS"
    checker_sha256 = next(
        component.sha256
        for component in gate.precommit.backend_components
        if component.path == "crates/quotient-forge-check/src/lib.rs"
    )
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "gate_status": gate_status,
        "bindings": {
            name: getattr(gate.precommit.bindings, name)
            for name in gate.precommit.bindings.__dataclass_fields__
        },
        "checker_sha256": checker_sha256,
        "equivalence_checker_sha256": gate.equivalence_checker_sha256,
        "seal_receipt_sha256": receipt_sha256(sealed_receipt),
        "minimum_held_out_valid_non_equivalent": (gate.minimum_held_out_valid_non_equivalent),
        "summary": {
            "held_out_case_count": len(gate.cases),
            "valid_non_equivalent_count": qualifying,
            "valid_equivalent_count": classes[DiscoveryClass.VALID_EQUIVALENT.value],
            "expected_nonrealizable_count": classes[DiscoveryClass.EXPECTED_NONREALIZABLE.value],
            "invalid_discovery_count": invalid,
            "status_disagreement_count": classes[DiscoveryClass.STATUS_DISAGREEMENT.value],
            "inconclusive_count": classes[DiscoveryClass.INCONCLUSIVE.value],
        },
        "cases": rows,
        "private_field_count": 0,
    }
    _reject_private_fields(manifest, "manifest")
    return manifest


def write_discovery_manifest(path: Path, manifest: Mapping[str, object]) -> Path:
    """Write canonical public evidence idempotently and refuse replacement."""

    _require_fields(manifest, MANIFEST_FIELDS, "manifest")
    _reject_private_fields(manifest, "manifest")
    payload = _canonical_json(manifest) + b"\n"
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("existing discovery manifest differs")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)
    return path


def main(arguments: Sequence[str] | None = None) -> int:
    """Create a checker-gated manifest from a sealed ledger and observations."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/quotient_forge/discovery_gate_v1.yaml"),
    )
    parser.add_argument("--seal-ledger", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)
    try:
        gate = load_discovery_gate(options.config)
        receipts = load_receipts(options.seal_ledger, precommit=gate.precommit)
        if len(receipts) != 1:
            raise DiscoveryManifestError("ledger must contain exactly one seal receipt")
        observations = load_discovery_observations(options.observations)
        manifest = build_discovery_manifest(gate, receipts[0], observations)
        write_discovery_manifest(options.output, manifest)
    except (DiscoveryManifestError, OSError, ValueError) as error:
        parser.error(str(error))
    return 0 if manifest["gate_status"] == "PASS" else 3


def _classify(case: GateCase, observation: DiscoveryObservation) -> DiscoveryClass:
    if observation.family_id != case.family_id:
        raise DiscoveryManifestError("observation family differs from gate case")
    if (
        observation.synthesis_status is SynthesisStatus.INCONCLUSIVE
        or observation.checker_status is CheckerStatus.INCONCLUSIVE
        or observation.template_relation is TemplateRelation.INCONCLUSIVE
    ):
        return DiscoveryClass.INCONCLUSIVE
    if case.author_template_sha256 is None:
        if observation.template_relation is not TemplateRelation.ABSENT:
            raise DiscoveryManifestError(f"template relation must be ABSENT: {case.family_id}")
    else:
        if observation.template_relation is TemplateRelation.ABSENT:
            raise DiscoveryManifestError(f"author template was omitted: {case.family_id}")
        if observation.template_machine_sha256 != case.author_template_sha256:
            raise DiscoveryManifestError(f"author template digest differs: {case.family_id}")

    if observation.synthesis_status.value != case.expected_status.value:
        return DiscoveryClass.STATUS_DISAGREEMENT
    if case.expected_status is not ExpectedStatus.REALIZABLE:
        if observation.checker_status is not CheckerStatus.NOT_RUN:
            return DiscoveryClass.INVALID_DISCOVERY
        return DiscoveryClass.EXPECTED_NONREALIZABLE
    if (
        observation.checker_status is not CheckerStatus.VERIFIED
        or observation.canonical_machine_sha256 is None
    ):
        return DiscoveryClass.INVALID_DISCOVERY
    if observation.template_relation is TemplateRelation.EQUIVALENT:
        return DiscoveryClass.VALID_EQUIVALENT
    if observation.template_relation is TemplateRelation.DISTINCT:
        return DiscoveryClass.VALID_NON_EQUIVALENT
    if observation.template_relation is TemplateRelation.ABSENT:
        return DiscoveryClass.VALID_UNTEMPLATED
    return DiscoveryClass.INCONCLUSIVE


def _parse_observation(value: object, index: int) -> DiscoveryObservation:
    mapping = _mapping(value, f"observations.cases[{index}]")
    _require_fields(mapping, OBSERVATION_FIELDS, f"observations.cases[{index}]")
    try:
        synthesis = SynthesisStatus(mapping["synthesis_status"])
        checker = CheckerStatus(mapping["checker_status"])
        relation = TemplateRelation(mapping["template_relation"])
        resource_reason = (
            None
            if mapping["resource_reason"] is None
            else ResourceReason(mapping["resource_reason"])
        )
    except (TypeError, ValueError) as error:
        raise DiscoveryManifestError("observation contains an unknown enum") from error
    machine_digest = _optional_digest(
        mapping["canonical_machine_sha256"], "canonical_machine_sha256"
    )
    template_digest = _optional_digest(
        mapping["template_machine_sha256"], "template_machine_sha256"
    )
    evidence_digest = _optional_digest(
        mapping["equivalence_evidence_sha256"], "equivalence_evidence_sha256"
    )
    inconclusive = (
        synthesis is SynthesisStatus.INCONCLUSIVE
        or checker is CheckerStatus.INCONCLUSIVE
        or relation is TemplateRelation.INCONCLUSIVE
    )
    if inconclusive != (resource_reason is not None):
        raise DiscoveryManifestError(
            "resource_reason is required exactly for inconclusive observations"
        )
    if synthesis is SynthesisStatus.REALIZABLE and machine_digest is None:
        raise DiscoveryManifestError("REALIZABLE observation requires a machine digest")
    if synthesis is not SynthesisStatus.REALIZABLE and machine_digest is not None:
        raise DiscoveryManifestError("non-realizable observation cannot carry a machine")
    if relation in {TemplateRelation.EQUIVALENT, TemplateRelation.DISTINCT}:
        if template_digest is None or evidence_digest is None:
            raise DiscoveryManifestError("template comparison requires both digests")
    elif relation is TemplateRelation.ABSENT:
        if template_digest is not None or evidence_digest is not None:
            raise DiscoveryManifestError("ABSENT template cannot carry equivalence digests")
    return DiscoveryObservation(
        family_id=_text(mapping["family_id"], "family_id"),
        synthesis_status=synthesis,
        checker_status=checker,
        canonical_machine_sha256=machine_digest,
        template_relation=relation,
        template_machine_sha256=template_digest,
        equivalence_evidence_sha256=evidence_digest,
        resource_reason=resource_reason,
    )


def _observation_mapping(
    case: GateCase,
    observation: DiscoveryObservation,
    classification: DiscoveryClass,
) -> dict[str, object]:
    return {
        "family_id": case.family_id,
        "expected_status": case.expected_status.value,
        "synthesis_status": observation.synthesis_status.value,
        "checker_status": observation.checker_status.value,
        "canonical_machine_sha256": observation.canonical_machine_sha256,
        "template_relation": observation.template_relation.value,
        "template_machine_sha256": observation.template_machine_sha256,
        "equivalence_evidence_sha256": observation.equivalence_evidence_sha256,
        "resource_reason": (
            None if observation.resource_reason is None else observation.resource_reason.value
        ),
        "classification": classification.value,
    }


def _normalized_file_sha256(path: Path) -> str:
    try:
        payload = path.read_bytes().replace(b"\r\n", b"\n")
    except OSError as error:
        raise DiscoveryManifestError("equivalence checker source is unavailable") from error
    if b"\r" in payload:
        raise DiscoveryManifestError("equivalence checker has non-canonical CR bytes")
    return hashlib.sha256(payload).hexdigest()


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise DiscoveryManifestError(f"cannot load YAML: {path}") from error
    return _mapping(document, str(path))


def _mapping(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise DiscoveryManifestError(f"{location} must be a string-keyed mapping")
    return dict(value)


def _require_fields(mapping: Mapping[str, object], expected: frozenset[str], location: str) -> None:
    if set(mapping) != expected:
        raise DiscoveryManifestError(f"{location} fields differ from the allowlist")


def _fixed_path(value: object, expected: str) -> str:
    if value != expected:
        raise DiscoveryManifestError(f"path must be {expected}")
    return expected


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value < 1:
        raise DiscoveryManifestError(f"{field} must be positive")
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise DiscoveryManifestError(f"{field} must be non-empty text")
    return value


def _optional_digest(value: object, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise DiscoveryManifestError(f"{field} must be lowercase SHA-256 or null")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _reject_private_fields(value: object, path: str) -> None:
    forbidden = {
        "private_history",
        "biosignal",
        "participant_id",
        "subject_id",
        "device_id",
        "token_bytes",
        "key_material",
        "username",
        "host_path",
        "absolute_path",
        "machine_cells",
        "raw_machine",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if normalized in forbidden:
                raise DiscoveryManifestError(f"forbidden public field: {path}.{key}")
            _reject_private_fields(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _reject_private_fields(child, f"{path}[{index}]")


if __name__ == "__main__":
    raise SystemExit(main())
