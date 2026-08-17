use quotient_forge_caqt::{
    artifact_digest, Certificate, CertificateLimits, Digest, InductiveCertificate,
    InductiveDecodeError, InductiveLimits, ParseError,
};
use quotient_seal_abi::{validate_wasm_abi, AbiVerdict, WasmSurfaceLimits};
use quotient_seal_context::{ProductVerdict, RelationBinding, CONTEXT_FAMILY_COUNT};
use quotient_seal_relation::{
    RelationCertificate, RelationDecodeError, RelationLimits, RelationVerdict,
};
use quotient_seal_resource::{NormalizationOverhead, ResourceVerdict};
use quotient_seal_target_ir::{
    parse_and_lower, target_ir_hash, CanonicalTargetIr, ConsensusVerdict, ParserLimits,
    TargetIrError,
};

use crate::format::{
    QsmCapsule, QsmContainerLimits, QsmDecodeError, QsmResourceBounds, QsmSectionTag,
};
use crate::manifest::{decode_abi_manifest, validate_observer_registry, CompilerManifest};

pub const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const RELATION_DIGEST_DOMAIN: &[u8] = b"noticer-core/quotient-seal/relation-certificate/v1";

pub struct SemanticRecomputeInput<'a> {
    pub source_certificate: &'a [u8],
    pub wasm_module: &'a [u8],
    pub observer_registry: &'a [u8],
    pub relation_certificate: &'a [u8],
    pub robust_certificate: &'a [u8],
    pub resource_certificate: &'a [u8],
    pub target_ir: &'a CanonicalTargetIr,
    pub resource_bounds: QsmResourceBounds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecomputedSemantics {
    pub parser_consensus: ConsensusVerdict,
    pub relation: RelationVerdict,
    pub context: ProductVerdict,
    pub resource: ResourceVerdict,
}

pub trait SemanticRecomputer {
    fn recompute(
        &self,
        input: SemanticRecomputeInput<'_>,
    ) -> Result<RecomputedSemantics, BackendFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailure {
    Unavailable,
    Protocol,
    ResourceBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsmResourceMode {
    Strict,
    Normalized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsmReport {
    pub capsule_digest: Digest,
    pub source_section_digest: Digest,
    pub wasm_section_digest: Digest,
    pub compiler_manifest_digest: Digest,
    pub target_ir_digest: Digest,
    pub relation_digest: Digest,
    pub relation_binding: RelationBinding,
    pub resource_mode: QsmResourceMode,
    pub checked_context_families: usize,
    pub checked_private_pairs: usize,
    pub checked_resource_cases: usize,
    pub hardware_status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QsmVerdict {
    Valid(Box<QsmReport>),
    Counterexample(QsmCounterexample),
    Invalid(QsmInvalid),
    Inconclusive(QsmInconclusive),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsmCounterexampleStage {
    Relation,
    Context,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QsmCounterexample {
    pub stage: QsmCounterexampleStage,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QsmInvalid {
    Container(QsmDecodeError),
    ResourceBounds,
    SourceCertificate,
    TargetModule,
    AbiManifest,
    Abi,
    ObserverRegistry,
    RelationCertificate,
    TargetBinding,
    CompilerManifest,
    SemanticBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsmInconclusive {
    SourceResourceBound,
    TargetResourceBound,
    AbiResourceBound,
    ParserConsensus,
    Backend(BackendFailure),
    Relation,
    Context,
    Resource,
}

#[must_use]
pub fn check_qsm<B: SemanticRecomputer + ?Sized>(
    bytes: &[u8],
    backend: &B,
    limits: QsmContainerLimits,
) -> QsmVerdict {
    let capsule = match QsmCapsule::decode(bytes, limits) {
        Ok(capsule) => capsule,
        Err(error) => return QsmVerdict::Invalid(QsmInvalid::Container(error)),
    };
    let bounds =
        match QsmResourceBounds::decode(capsule.section(QsmSectionTag::ResourceBounds).payload()) {
            Ok(bounds) if bounds.validate(limits.hard_bounds).is_ok() => bounds,
            Ok(_) | Err(_) => return QsmVerdict::Invalid(QsmInvalid::ResourceBounds),
        };

    let source_bytes = capsule.section(QsmSectionTag::SourceCertificate).payload();
    let source_limits = InductiveLimits {
        max_bytes: bounded_usize(bounds.max_source_certificate_bytes),
        max_base_bytes: bounded_usize(bounds.max_source_certificate_bytes),
        max_product_states: bounded_usize(bounds.max_context_product_states),
        max_closure_records: bounded_usize(bounds.max_relation_cases),
        base_limits: CertificateLimits {
            max_bytes: bounded_usize(bounds.max_source_certificate_bytes),
            ..CertificateLimits::default()
        },
    };
    let source = match InductiveCertificate::decode(source_bytes, source_limits) {
        Ok(certificate) => certificate,
        Err(InductiveDecodeError::ResourceBound(_)) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::SourceResourceBound);
        }
        Err(InductiveDecodeError::Parse(_)) => {
            return QsmVerdict::Invalid(QsmInvalid::SourceCertificate);
        }
    };
    if source.encode() != source_bytes {
        return QsmVerdict::Invalid(QsmInvalid::SourceCertificate);
    }
    let base = match Certificate::decode(&source.base_certificate, source_limits.base_limits) {
        Ok(certificate) => certificate,
        Err(
            ParseError::SizeLimit { .. }
            | ParseError::RecordLimit { .. }
            | ParseError::PayloadLimit { .. }
            | ParseError::ActionLimit { .. },
        ) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::SourceResourceBound);
        }
        Err(_) => return QsmVerdict::Invalid(QsmInvalid::SourceCertificate),
    };
    if base.encode() != source.base_certificate {
        return QsmVerdict::Invalid(QsmInvalid::SourceCertificate);
    }

    let wasm = capsule.section(QsmSectionTag::WasmModule).payload();
    let parser_limits = ParserLimits {
        max_module_bytes: bounded_usize(bounds.max_wasm_bytes),
        max_sections: bounded_u32(bounds.max_parser_sections),
        ..ParserLimits::frozen_v1()
    };
    let target_ir = match parse_and_lower(wasm, parser_limits) {
        Ok(target) => target,
        Err(TargetIrError::ResourceBound(_)) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::TargetResourceBound);
        }
        Err(TargetIrError::Invalid(_) | TargetIrError::Incompatible(_)) => {
            return QsmVerdict::Invalid(QsmInvalid::TargetModule);
        }
    };
    let target_digest = target_ir_hash(&target_ir);

    let abi_manifest =
        match decode_abi_manifest(capsule.section(QsmSectionTag::AbiManifest).payload()) {
            Ok(manifest) => manifest,
            Err(_) => return QsmVerdict::Invalid(QsmInvalid::AbiManifest),
        };
    let abi_limits = WasmSurfaceLimits {
        max_bytes: bounded_usize(bounds.max_wasm_bytes),
        max_sections: bounded_usize(bounds.max_parser_sections),
        ..WasmSurfaceLimits::default()
    };
    match validate_wasm_abi(wasm, abi_manifest, abi_limits) {
        AbiVerdict::Valid(_) => {}
        AbiVerdict::Invalid(_) | AbiVerdict::Incompatible(_) => {
            return QsmVerdict::Invalid(QsmInvalid::Abi);
        }
        AbiVerdict::ResourceBound(_) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::AbiResourceBound);
        }
    }

    let observer = capsule.section(QsmSectionTag::ObserverRegistry).payload();
    if !validate_observer_registry(observer) {
        return QsmVerdict::Invalid(QsmInvalid::ObserverRegistry);
    }

    let relation_bytes = capsule
        .section(QsmSectionTag::RelationCertificate)
        .payload();
    let relation_limits = RelationLimits {
        max_bytes: bounded_usize(bounds.max_relation_certificate_bytes),
        max_records: bounded_usize(bounds.max_relation_cases),
        ..RelationLimits::default()
    };
    let relation_certificate = match RelationCertificate::decode(relation_bytes, relation_limits) {
        Ok(certificate) => certificate,
        Err(error) if relation_resource_bound(error) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::Relation);
        }
        Err(_) => return QsmVerdict::Invalid(QsmInvalid::RelationCertificate),
    };
    if relation_certificate.encode() != relation_bytes {
        return QsmVerdict::Invalid(QsmInvalid::RelationCertificate);
    }
    if relation_certificate.target_ir_digest != target_digest {
        return QsmVerdict::Invalid(QsmInvalid::TargetBinding);
    }

    if CompilerManifest::decode(capsule.section(QsmSectionTag::CompilerManifest).payload()).is_err()
    {
        return QsmVerdict::Invalid(QsmInvalid::CompilerManifest);
    }

    let recomputed = match backend.recompute(SemanticRecomputeInput {
        source_certificate: source_bytes,
        wasm_module: wasm,
        observer_registry: observer,
        relation_certificate: relation_bytes,
        robust_certificate: capsule.section(QsmSectionTag::RobustCertificate).payload(),
        resource_certificate: capsule
            .section(QsmSectionTag::ResourceCertificate)
            .payload(),
        target_ir: &target_ir,
        resource_bounds: bounds,
    }) {
        Ok(recomputed) => recomputed,
        Err(error) => return QsmVerdict::Inconclusive(QsmInconclusive::Backend(error)),
    };

    match recomputed.parser_consensus {
        ConsensusVerdict::Valid(digest) if digest == target_digest => {}
        ConsensusVerdict::Valid(_) => return QsmVerdict::Invalid(QsmInvalid::SemanticBinding),
        ConsensusVerdict::Invalid
        | ConsensusVerdict::ResourceBound
        | ConsensusVerdict::Unresolved => {
            return QsmVerdict::Inconclusive(QsmInconclusive::ParserConsensus);
        }
    }

    let expected_relation_digest = artifact_digest(RELATION_DIGEST_DOMAIN, relation_bytes);
    let relation_report = match &recomputed.relation {
        RelationVerdict::Valid(report)
            if report.target_ir_digest == target_digest
                && report.relation_digest == expected_relation_digest
                && report.inductive_digest == relation_certificate.inductive_digest
                && report.reachable_states > 0
                && report.checked_source_steps > 0
                && report.checked_two_run_cases > 0 =>
        {
            report
        }
        RelationVerdict::Valid(_) => {
            return QsmVerdict::Invalid(QsmInvalid::SemanticBinding);
        }
        RelationVerdict::Invalid(counterexample) => {
            return QsmVerdict::Counterexample(QsmCounterexample {
                stage: QsmCounterexampleStage::Relation,
                evidence_digest: artifact_digest(
                    b"noticer-core/qseal/relation-counterexample/v1",
                    &counterexample.encode(),
                ),
            });
        }
        RelationVerdict::Incompatible(_)
        | RelationVerdict::ResourceBound(_)
        | RelationVerdict::Unresolved(_) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::Relation);
        }
    };
    let binding = RelationBinding::from_report(relation_report);

    let context_report = match &recomputed.context {
        ProductVerdict::Accept(report)
            if report.binding == binding
                && report.observer_profiles == 7
                && report.context_families == CONTEXT_FAMILY_COUNT
                && report.private_pairs > 0
                && report.induction_closed =>
        {
            report
        }
        ProductVerdict::Accept(_) => {
            return QsmVerdict::Invalid(QsmInvalid::SemanticBinding);
        }
        ProductVerdict::Counterexample(counterexample) => {
            return QsmVerdict::Counterexample(QsmCounterexample {
                stage: QsmCounterexampleStage::Context,
                evidence_digest: counterexample.digest(),
            });
        }
        ProductVerdict::Inconclusive(_) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::Context);
        }
    };

    let (resource_mode, resource_report) = match &recomputed.resource {
        ResourceVerdict::Strict(report)
            if report.pre_binding == binding
                && report.post_binding == binding
                && report.checked_cases > 0
                && report.candidate_digest.is_none()
                && report.overhead == NormalizationOverhead::default() =>
        {
            (QsmResourceMode::Strict, report)
        }
        ResourceVerdict::Normalized(report)
            if report.post_binding == binding
                && report.checked_cases > 0
                && report.candidate_digest.is_some()
                && overhead_within_bounds(report.overhead, bounds) =>
        {
            (QsmResourceMode::Normalized, report)
        }
        ResourceVerdict::Strict(_) | ResourceVerdict::Normalized(_) => {
            return QsmVerdict::Invalid(QsmInvalid::SemanticBinding);
        }
        ResourceVerdict::Counterexample(counterexample) => {
            return QsmVerdict::Counterexample(QsmCounterexample {
                stage: QsmCounterexampleStage::Resource,
                evidence_digest: counterexample.digest(),
            });
        }
        ResourceVerdict::Inconclusive(_) => {
            return QsmVerdict::Inconclusive(QsmInconclusive::Resource);
        }
    };

    QsmVerdict::Valid(Box::new(QsmReport {
        capsule_digest: capsule.digest(),
        source_section_digest: capsule.section(QsmSectionTag::SourceCertificate).digest,
        wasm_section_digest: capsule.section(QsmSectionTag::WasmModule).digest,
        compiler_manifest_digest: capsule.section(QsmSectionTag::CompilerManifest).digest,
        target_ir_digest: target_digest,
        relation_digest: expected_relation_digest,
        relation_binding: binding,
        resource_mode,
        checked_context_families: context_report.context_families,
        checked_private_pairs: context_report.private_pairs,
        checked_resource_cases: resource_report.checked_cases,
        hardware_status: HARDWARE_STATUS,
    }))
}

const fn bounded_usize(value: u64) -> usize {
    if value > usize::MAX as u64 {
        usize::MAX
    } else {
        value as usize
    }
}

const fn bounded_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

const fn overhead_within_bounds(
    overhead: NormalizationOverhead,
    bounds: QsmResourceBounds,
) -> bool {
    overhead.operation_count as u128 <= bounds.max_pad_operations as u128
        && overhead.added_instructions <= bounds.max_added_instructions
        && overhead.added_fuel <= bounds.max_added_fuel
        && overhead.fixed_scratch_bytes <= bounds.max_scratch_bytes
}

const fn relation_resource_bound(error: RelationDecodeError) -> bool {
    matches!(
        error,
        RelationDecodeError::SizeLimit { .. }
            | RelationDecodeError::RecordLimit { .. }
            | RelationDecodeError::PcLimit { .. }
            | RelationDecodeError::GlobalLimit { .. }
            | RelationDecodeError::MemoryPredicateLimit { .. }
            | RelationDecodeError::WriteRangeLimit { .. }
            | RelationDecodeError::PredicateBytesLimit { .. }
    )
}
