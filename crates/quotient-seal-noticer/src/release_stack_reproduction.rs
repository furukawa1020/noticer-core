use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::{
    DifferentialDifference, DifferentialDifferenceKind, DifferentialEvidenceOrigin,
    DifferentialUnresolvedReason, EngineArtifactDigests, ModuleDifferentialEvidence,
    NoticerModuleId, ReleaseStackDifferentialArtifact, ReleaseStackDifferentialBindings,
    ReleaseStackDifferentialError, ReleaseStackDifferentialVerdict,
};

pub const RELEASE_STACK_REPRODUCTION_SCHEMA: &str = "noticer.release_stack.reproduction.v1";
pub const RELEASE_STACK_REPRODUCTION_COMMAND: &str = "cargo run -p quotient-seal-noticer --example release_stack_reproduction -- --output artifacts/release_stack";
const DOMAIN: &[u8] = b"NOTICER_RELEASE_STACK_REPRODUCTION_V1";
const COMPONENT_COUNT: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackComponentKind {
    Config,
    CompositionContract,
    CanonicalPath,
    ProfileGate,
    AdversarialMatrix,
    DifferentialOracle,
}

impl ReleaseStackComponentKind {
    const ALL: [Self; COMPONENT_COUNT] = [
        Self::Config,
        Self::CompositionContract,
        Self::CanonicalPath,
        Self::ProfileGate,
        Self::AdversarialMatrix,
        Self::DifferentialOracle,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseStackComponentBinding {
    pub kind: ReleaseStackComponentKind,
    pub artifact_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackCaseProfile {
    P0,
    P1,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackCaseVerdict {
    Match,
    AttackRejected,
    ProfileUnresolved,
    InvariantViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseStackFirstDifference {
    pub case_id_sha256: [u8; 32],
    pub module: NoticerModuleId,
    pub kind: DifferentialDifferenceKind,
    pub step_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseStackCaseReceipt {
    pub case_id_sha256: [u8; 32],
    pub case_artifact_sha256: [u8; 32],
    pub profile: ReleaseStackCaseProfile,
    pub verdict: ReleaseStackCaseVerdict,
    pub action_count: u32,
    pub frame_count: u32,
    pub failure_count: u32,
    pub first_difference: Option<DifferentialDifference>,
    pub first_difference_module: Option<NoticerModuleId>,
    pub evidence_origin: DifferentialEvidenceOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackReproductionVerdict {
    Complete,
    Counterexample,
    Unresolved,
    InvariantViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackHardwareStatus {
    NotVerified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseStackReproductionSummary {
    pub verdict: ReleaseStackReproductionVerdict,
    pub case_count: u32,
    pub match_count: u32,
    pub attack_rejected_count: u32,
    pub profile_unresolved_count: u32,
    pub invariant_violation_count: u32,
    pub action_count: u64,
    pub frame_count: u64,
    pub failure_count: u64,
    pub first_difference: Option<ReleaseStackFirstDifference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseStackReproductionInputs {
    pub source_tree_sha256: [u8; 32],
    pub seed: u64,
    pub components: [ReleaseStackComponentBinding; COMPONENT_COUNT],
    pub cases: Vec<ReleaseStackCaseReceipt>,
    pub differential: ReleaseStackDifferentialArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseStackReproductionBundle {
    pub schema: &'static str,
    pub reproduction_command: &'static str,
    pub source_tree_sha256: [u8; 32],
    pub seed: u64,
    pub hardware_status: ReleaseStackHardwareStatus,
    pub components: [ReleaseStackComponentBinding; COMPONENT_COUNT],
    pub cases: Vec<ReleaseStackCaseReceipt>,
    pub differential: ReleaseStackDifferentialArtifact,
    pub summary: ReleaseStackReproductionSummary,
    pub artifact_sha256: [u8; 32],
}

impl ReleaseStackReproductionBundle {
    pub fn build(
        inputs: ReleaseStackReproductionInputs,
    ) -> Result<Self, ReleaseStackReproductionError> {
        validate_inputs(&inputs)?;
        let summary = summarize(&inputs.cases, &inputs.differential)?;
        let mut bundle = Self {
            schema: RELEASE_STACK_REPRODUCTION_SCHEMA,
            reproduction_command: RELEASE_STACK_REPRODUCTION_COMMAND,
            source_tree_sha256: inputs.source_tree_sha256,
            seed: inputs.seed,
            hardware_status: ReleaseStackHardwareStatus::NotVerified,
            components: inputs.components,
            cases: inputs.cases,
            differential: inputs.differential,
            summary,
            artifact_sha256: [0; 32],
        };
        bundle.artifact_sha256 = bundle.recomputed_sha256();
        Ok(bundle)
    }

    pub fn verify_internal_recomputation(&self) -> Result<(), ReleaseStackReproductionError> {
        self.verify_complete_recomputation(&self.inputs())
    }

    pub fn verify_complete_recomputation(
        &self,
        expected_inputs: &ReleaseStackReproductionInputs,
    ) -> Result<(), ReleaseStackReproductionError> {
        let expected = Self::build(expected_inputs.clone())?;
        if self.canonical_json() != expected.canonical_json() {
            return Err(ReleaseStackReproductionError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn inputs(&self) -> ReleaseStackReproductionInputs {
        ReleaseStackReproductionInputs {
            source_tree_sha256: self.source_tree_sha256,
            seed: self.seed,
            components: self.components,
            cases: self.cases.clone(),
            differential: self.differential.clone(),
        }
    }

    pub fn recomputed_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.canonical_payload_json().as_bytes());
        hasher.finalize().into()
    }

    pub fn canonical_json(&self) -> String {
        let mut json = self.canonical_payload_json();
        let removed = json.pop();
        debug_assert_eq!(removed, Some('}'));
        write!(
            json,
            ",\"artifact_sha256\":\"{}\"}}",
            hex(&self.artifact_sha256)
        )
        .expect("writing to String cannot fail");
        json
    }

    pub fn machine_summary_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"artifact_sha256\":\"{}\",\"seed\":{},\"verdict\":\"{}\",\"case_count\":{},\"match_count\":{},\"attack_rejected_count\":{},\"profile_unresolved_count\":{},\"invariant_violation_count\":{},\"action_count\":{},\"frame_count\":{},\"failure_count\":{},\"first_difference\":{},\"hardware_status\":\"NOT_VERIFIED\"}}",
            self.schema,
            hex(&self.artifact_sha256),
            self.seed,
            reproduction_verdict_name(self.summary.verdict),
            self.summary.case_count,
            self.summary.match_count,
            self.summary.attack_rejected_count,
            self.summary.profile_unresolved_count,
            self.summary.invariant_violation_count,
            self.summary.action_count,
            self.summary.frame_count,
            self.summary.failure_count,
            first_difference_json(self.summary.first_difference),
        )
    }

    pub fn write_artifacts(&self, output_directory: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
        std::fs::create_dir_all(output_directory)?;
        let bundle_path = output_directory.join("release_stack_bundle.json");
        let summary_path = output_directory.join("release_stack_summary.json");
        std::fs::write(&bundle_path, self.canonical_json().as_bytes())?;
        std::fs::write(&summary_path, self.machine_summary_json().as_bytes())?;
        Ok((bundle_path, summary_path))
    }

    fn canonical_payload_json(&self) -> String {
        let mut json = String::new();
        write!(
            json,
            "{{\"schema\":\"{}\",\"reproduction_command\":\"{}\",\"source_tree_sha256\":\"{}\",\"seed\":{},\"hardware_status\":\"NOT_VERIFIED\",\"components\":[",
            self.schema,
            self.reproduction_command,
            hex(&self.source_tree_sha256),
            self.seed,
        )
        .expect("writing to String cannot fail");
        for (index, component) in self.components.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            write!(
                json,
                "{{\"kind\":\"{}\",\"artifact_sha256\":\"{}\"}}",
                component_name(component.kind),
                hex(&component.artifact_sha256),
            )
            .expect("writing to String cannot fail");
        }
        json.push_str("],\"cases\":[");
        for (index, case) in self.cases.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            write_case_json(&mut json, case);
        }
        json.push_str("],\"differential\":");
        write_differential_json(&mut json, &self.differential);
        json.push_str(",\"summary\":");
        write_summary_json(&mut json, &self.summary);
        json.push('}');
        json
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseStackReproductionError {
    ZeroSourceTreeDigest,
    UnexpectedComponent {
        index: usize,
        expected: ReleaseStackComponentKind,
        actual: ReleaseStackComponentKind,
    },
    MissingComponentArtifact(ReleaseStackComponentKind),
    CrossBindingMismatch(ReleaseStackComponentKind),
    MissingCases,
    NonCanonicalCaseOrder,
    MissingCaseArtifact,
    InvalidCaseReceipt,
    CountOverflow,
    Differential(ReleaseStackDifferentialError),
    ArtifactMismatch,
}

impl fmt::Display for ReleaseStackReproductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSourceTreeDigest => write!(formatter, "zero source tree digest"),
            Self::UnexpectedComponent { index, .. } => {
                write!(formatter, "unexpected component at canonical index {index}")
            }
            Self::MissingComponentArtifact(_) => write!(formatter, "missing component artifact"),
            Self::CrossBindingMismatch(_) => write!(formatter, "component cross-binding mismatch"),
            Self::MissingCases => write!(formatter, "release stack case set is empty"),
            Self::NonCanonicalCaseOrder => write!(formatter, "case IDs are not strictly ordered"),
            Self::MissingCaseArtifact => write!(formatter, "case artifact is missing"),
            Self::InvalidCaseReceipt => write!(formatter, "case receipt is inconsistent"),
            Self::CountOverflow => write!(formatter, "summary count overflow"),
            Self::Differential(error) => {
                write!(formatter, "invalid differential artifact: {error}")
            }
            Self::ArtifactMismatch => write!(formatter, "bundle differs from full recomputation"),
        }
    }
}

impl std::error::Error for ReleaseStackReproductionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Differential(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ReleaseStackDifferentialError> for ReleaseStackReproductionError {
    fn from(error: ReleaseStackDifferentialError) -> Self {
        Self::Differential(error)
    }
}

pub fn injected_reproduction_fixture_inputs(
) -> Result<ReleaseStackReproductionInputs, ReleaseStackReproductionError> {
    let bindings = ReleaseStackDifferentialBindings {
        manifest_sha256: fixture_digest(1),
        composition_contract_sha256: fixture_digest(2),
        path_contract_sha256: fixture_digest(3),
        profile_contract_sha256: fixture_digest(4),
    };
    let modules = std::array::from_fn(|index| {
        let base = 10 + (index as u8 * 4);
        ModuleDifferentialEvidence::from_existing_artifact(
            NoticerModuleId::ALL[index],
            fixture_digest(base),
            EngineArtifactDigests {
                reference_sha256: fixture_digest(base + 1),
                wasmi_sha256: fixture_digest(base + 2),
                wasmtime_sha256: fixture_digest(base + 3),
            },
            ReleaseStackDifferentialVerdict::Match,
            None,
            None,
            DifferentialEvidenceOrigin::InjectedTestFixture,
        )
    });
    let differential = ReleaseStackDifferentialArtifact::evaluate(bindings, modules)?;
    let components = [
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::Config,
            artifact_sha256: fixture_digest(40),
        },
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::CompositionContract,
            artifact_sha256: bindings.composition_contract_sha256,
        },
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::CanonicalPath,
            artifact_sha256: bindings.path_contract_sha256,
        },
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::ProfileGate,
            artifact_sha256: bindings.profile_contract_sha256,
        },
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::AdversarialMatrix,
            artifact_sha256: fixture_digest(41),
        },
        ReleaseStackComponentBinding {
            kind: ReleaseStackComponentKind::DifferentialOracle,
            artifact_sha256: differential.artifact_sha256,
        },
    ];
    let cases = vec![
        ReleaseStackCaseReceipt {
            case_id_sha256: fixture_digest(50),
            case_artifact_sha256: fixture_digest(51),
            profile: ReleaseStackCaseProfile::P0,
            verdict: ReleaseStackCaseVerdict::Match,
            action_count: 1,
            frame_count: 5,
            failure_count: 0,
            first_difference: None,
            first_difference_module: None,
            evidence_origin: DifferentialEvidenceOrigin::InjectedTestFixture,
        },
        ReleaseStackCaseReceipt {
            case_id_sha256: fixture_digest(52),
            case_artifact_sha256: fixture_digest(53),
            profile: ReleaseStackCaseProfile::P0,
            verdict: ReleaseStackCaseVerdict::AttackRejected,
            action_count: 0,
            frame_count: 2,
            failure_count: 1,
            first_difference: Some(DifferentialDifference {
                kind: DifferentialDifferenceKind::HostCall,
                step_index: 2,
            }),
            first_difference_module: Some(NoticerModuleId::Atv2FramePlanner),
            evidence_origin: DifferentialEvidenceOrigin::InjectedTestFixture,
        },
    ];
    Ok(ReleaseStackReproductionInputs {
        source_tree_sha256: fixture_digest(60),
        seed: 0x4e4f_5449_4345_5255,
        components,
        cases,
        differential,
    })
}

fn validate_inputs(
    inputs: &ReleaseStackReproductionInputs,
) -> Result<(), ReleaseStackReproductionError> {
    if inputs.source_tree_sha256 == [0; 32] {
        return Err(ReleaseStackReproductionError::ZeroSourceTreeDigest);
    }
    inputs.differential.verify_complete_recomputation()?;
    for (index, component) in inputs.components.iter().enumerate() {
        let expected = ReleaseStackComponentKind::ALL[index];
        if component.kind != expected {
            return Err(ReleaseStackReproductionError::UnexpectedComponent {
                index,
                expected,
                actual: component.kind,
            });
        }
        if component.artifact_sha256 == [0; 32] {
            return Err(ReleaseStackReproductionError::MissingComponentArtifact(
                component.kind,
            ));
        }
    }
    for (kind, expected) in [
        (
            ReleaseStackComponentKind::CompositionContract,
            inputs.differential.bindings.composition_contract_sha256,
        ),
        (
            ReleaseStackComponentKind::CanonicalPath,
            inputs.differential.bindings.path_contract_sha256,
        ),
        (
            ReleaseStackComponentKind::ProfileGate,
            inputs.differential.bindings.profile_contract_sha256,
        ),
        (
            ReleaseStackComponentKind::DifferentialOracle,
            inputs.differential.artifact_sha256,
        ),
    ] {
        let actual = inputs.components[component_index(kind)].artifact_sha256;
        if actual != expected {
            return Err(ReleaseStackReproductionError::CrossBindingMismatch(kind));
        }
    }
    validate_cases(&inputs.cases)
}

fn validate_cases(cases: &[ReleaseStackCaseReceipt]) -> Result<(), ReleaseStackReproductionError> {
    if cases.is_empty() {
        return Err(ReleaseStackReproductionError::MissingCases);
    }
    if cases
        .windows(2)
        .any(|pair| pair[0].case_id_sha256 >= pair[1].case_id_sha256)
    {
        return Err(ReleaseStackReproductionError::NonCanonicalCaseOrder);
    }
    for case in cases {
        if case.case_id_sha256 == [0; 32] || case.case_artifact_sha256 == [0; 32] {
            return Err(ReleaseStackReproductionError::MissingCaseArtifact);
        }
        let difference_consistent =
            case.first_difference.is_some() == case.first_difference_module.is_some();
        let verdict_consistent = match case.verdict {
            ReleaseStackCaseVerdict::Match => {
                case.profile != ReleaseStackCaseProfile::Unresolved
                    && case.failure_count == 0
                    && case.first_difference.is_none()
            }
            ReleaseStackCaseVerdict::AttackRejected => {
                case.profile != ReleaseStackCaseProfile::Unresolved
                    && case.action_count == 0
                    && case.failure_count > 0
                    && case.first_difference.is_some()
            }
            ReleaseStackCaseVerdict::ProfileUnresolved => {
                case.profile == ReleaseStackCaseProfile::Unresolved
                    && case.action_count == 0
                    && case.failure_count > 0
                    && case.first_difference.is_some()
            }
            ReleaseStackCaseVerdict::InvariantViolation => {
                case.failure_count > 0 && case.first_difference.is_some()
            }
        };
        if !difference_consistent || !verdict_consistent {
            return Err(ReleaseStackReproductionError::InvalidCaseReceipt);
        }
    }
    Ok(())
}

fn summarize(
    cases: &[ReleaseStackCaseReceipt],
    differential: &ReleaseStackDifferentialArtifact,
) -> Result<ReleaseStackReproductionSummary, ReleaseStackReproductionError> {
    let mut summary = ReleaseStackReproductionSummary {
        verdict: ReleaseStackReproductionVerdict::Complete,
        case_count: u32::try_from(cases.len())
            .map_err(|_| ReleaseStackReproductionError::CountOverflow)?,
        match_count: 0,
        attack_rejected_count: 0,
        profile_unresolved_count: 0,
        invariant_violation_count: 0,
        action_count: 0,
        frame_count: 0,
        failure_count: 0,
        first_difference: None,
    };
    for case in cases {
        let counter = match case.verdict {
            ReleaseStackCaseVerdict::Match => &mut summary.match_count,
            ReleaseStackCaseVerdict::AttackRejected => &mut summary.attack_rejected_count,
            ReleaseStackCaseVerdict::ProfileUnresolved => &mut summary.profile_unresolved_count,
            ReleaseStackCaseVerdict::InvariantViolation => &mut summary.invariant_violation_count,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(ReleaseStackReproductionError::CountOverflow)?;
        summary.action_count = summary
            .action_count
            .checked_add(u64::from(case.action_count))
            .ok_or(ReleaseStackReproductionError::CountOverflow)?;
        summary.frame_count = summary
            .frame_count
            .checked_add(u64::from(case.frame_count))
            .ok_or(ReleaseStackReproductionError::CountOverflow)?;
        summary.failure_count = summary
            .failure_count
            .checked_add(u64::from(case.failure_count))
            .ok_or(ReleaseStackReproductionError::CountOverflow)?;
        if summary.first_difference.is_none() {
            if let (Some(difference), Some(module)) =
                (case.first_difference, case.first_difference_module)
            {
                summary.first_difference = Some(ReleaseStackFirstDifference {
                    case_id_sha256: case.case_id_sha256,
                    module,
                    kind: difference.kind,
                    step_index: difference.step_index,
                });
            }
        }
    }
    summary.verdict = if summary.invariant_violation_count > 0 {
        ReleaseStackReproductionVerdict::InvariantViolation
    } else {
        match differential.verdict {
            ReleaseStackDifferentialVerdict::Match => ReleaseStackReproductionVerdict::Complete,
            ReleaseStackDifferentialVerdict::Counterexample => {
                ReleaseStackReproductionVerdict::Counterexample
            }
            ReleaseStackDifferentialVerdict::Unresolved => {
                ReleaseStackReproductionVerdict::Unresolved
            }
        }
    };
    Ok(summary)
}

fn write_case_json(json: &mut String, case: &ReleaseStackCaseReceipt) {
    write!(
        json,
        "{{\"case_id_sha256\":\"{}\",\"case_artifact_sha256\":\"{}\",\"profile\":\"{}\",\"verdict\":\"{}\",\"action_count\":{},\"frame_count\":{},\"failure_count\":{},\"first_difference\":{},\"first_difference_module\":{},\"evidence_origin\":\"{}\"}}",
        hex(&case.case_id_sha256),
        hex(&case.case_artifact_sha256),
        case_profile_name(case.profile),
        case_verdict_name(case.verdict),
        case.action_count,
        case.frame_count,
        case.failure_count,
        difference_json(case.first_difference),
        optional_module_json(case.first_difference_module),
        origin_name(case.evidence_origin),
    )
    .expect("writing to String cannot fail");
}

fn write_differential_json(json: &mut String, artifact: &ReleaseStackDifferentialArtifact) {
    write!(
        json,
        "{{\"schema\":\"{}\",\"artifact_sha256\":\"{}\",\"verdict\":\"{}\",\"first_counterexample_module\":{},\"first_unresolved_module\":{},\"evidence_origin\":\"{}\",\"bindings\":{{\"manifest_sha256\":\"{}\",\"composition_contract_sha256\":\"{}\",\"path_contract_sha256\":\"{}\",\"profile_contract_sha256\":\"{}\"}},\"modules\":[",
        artifact.schema,
        hex(&artifact.artifact_sha256),
        differential_verdict_name(artifact.verdict),
        optional_module_json(artifact.first_counterexample_module),
        optional_module_json(artifact.first_unresolved_module),
        origin_name(artifact.evidence_origin),
        hex(&artifact.bindings.manifest_sha256),
        hex(&artifact.bindings.composition_contract_sha256),
        hex(&artifact.bindings.path_contract_sha256),
        hex(&artifact.bindings.profile_contract_sha256),
    )
    .expect("writing to String cannot fail");
    for (index, module) in artifact.modules.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        write!(
            json,
            "{{\"module\":\"{}\",\"module_artifact_sha256\":\"{}\",\"reference_sha256\":\"{}\",\"wasmi_sha256\":\"{}\",\"wasmtime_sha256\":\"{}\",\"verdict\":\"{}\",\"first_difference\":{},\"unresolved_reason\":{},\"evidence_origin\":\"{}\"}}",
            module_name(module.module),
            hex(&module.module_artifact_sha256),
            hex(&module.engines.reference_sha256),
            hex(&module.engines.wasmi_sha256),
            hex(&module.engines.wasmtime_sha256),
            differential_verdict_name(module.verdict),
            difference_json(module.first_difference),
            unresolved_json(module.unresolved_reason),
            origin_name(module.evidence_origin),
        )
        .expect("writing to String cannot fail");
    }
    json.push_str("]}");
}

fn write_summary_json(json: &mut String, summary: &ReleaseStackReproductionSummary) {
    write!(
        json,
        "{{\"verdict\":\"{}\",\"case_count\":{},\"match_count\":{},\"attack_rejected_count\":{},\"profile_unresolved_count\":{},\"invariant_violation_count\":{},\"action_count\":{},\"frame_count\":{},\"failure_count\":{},\"first_difference\":{}}}",
        reproduction_verdict_name(summary.verdict),
        summary.case_count,
        summary.match_count,
        summary.attack_rejected_count,
        summary.profile_unresolved_count,
        summary.invariant_violation_count,
        summary.action_count,
        summary.frame_count,
        summary.failure_count,
        first_difference_json(summary.first_difference),
    )
    .expect("writing to String cannot fail");
}

fn first_difference_json(difference: Option<ReleaseStackFirstDifference>) -> String {
    difference.map_or_else(
        || "null".to_owned(),
        |difference| {
            format!(
                "{{\"case_id_sha256\":\"{}\",\"module\":\"{}\",\"kind\":\"{}\",\"step_index\":{}}}",
                hex(&difference.case_id_sha256),
                module_name(difference.module),
                difference_name(difference.kind),
                difference.step_index,
            )
        },
    )
}

fn difference_json(difference: Option<DifferentialDifference>) -> String {
    difference.map_or_else(
        || "null".to_owned(),
        |difference| {
            format!(
                "{{\"kind\":\"{}\",\"step_index\":{}}}",
                difference_name(difference.kind),
                difference.step_index,
            )
        },
    )
}

fn optional_module_json(module: Option<NoticerModuleId>) -> String {
    module.map_or_else(
        || "null".to_owned(),
        |module| format!("\"{}\"", module_name(module)),
    )
}

fn unresolved_json(reason: Option<DifferentialUnresolvedReason>) -> String {
    reason.map_or_else(
        || "null".to_owned(),
        |reason| format!("\"{}\"", unresolved_name(reason)),
    )
}

fn component_index(kind: ReleaseStackComponentKind) -> usize {
    match kind {
        ReleaseStackComponentKind::Config => 0,
        ReleaseStackComponentKind::CompositionContract => 1,
        ReleaseStackComponentKind::CanonicalPath => 2,
        ReleaseStackComponentKind::ProfileGate => 3,
        ReleaseStackComponentKind::AdversarialMatrix => 4,
        ReleaseStackComponentKind::DifferentialOracle => 5,
    }
}

fn component_name(kind: ReleaseStackComponentKind) -> &'static str {
    match kind {
        ReleaseStackComponentKind::Config => "CONFIG",
        ReleaseStackComponentKind::CompositionContract => "COMPOSITION_CONTRACT",
        ReleaseStackComponentKind::CanonicalPath => "CANONICAL_PATH",
        ReleaseStackComponentKind::ProfileGate => "PROFILE_GATE",
        ReleaseStackComponentKind::AdversarialMatrix => "ADVERSARIAL_MATRIX",
        ReleaseStackComponentKind::DifferentialOracle => "DIFFERENTIAL_ORACLE",
    }
}

fn case_profile_name(profile: ReleaseStackCaseProfile) -> &'static str {
    match profile {
        ReleaseStackCaseProfile::P0 => "P0",
        ReleaseStackCaseProfile::P1 => "P1",
        ReleaseStackCaseProfile::Unresolved => "UNRESOLVED",
    }
}

fn case_verdict_name(verdict: ReleaseStackCaseVerdict) -> &'static str {
    match verdict {
        ReleaseStackCaseVerdict::Match => "MATCH",
        ReleaseStackCaseVerdict::AttackRejected => "ATTACK_REJECTED",
        ReleaseStackCaseVerdict::ProfileUnresolved => "PROFILE_UNRESOLVED",
        ReleaseStackCaseVerdict::InvariantViolation => "INVARIANT_VIOLATION",
    }
}

fn reproduction_verdict_name(verdict: ReleaseStackReproductionVerdict) -> &'static str {
    match verdict {
        ReleaseStackReproductionVerdict::Complete => "COMPLETE",
        ReleaseStackReproductionVerdict::Counterexample => "COUNTEREXAMPLE",
        ReleaseStackReproductionVerdict::Unresolved => "UNRESOLVED",
        ReleaseStackReproductionVerdict::InvariantViolation => "INVARIANT_VIOLATION",
    }
}

fn differential_verdict_name(verdict: ReleaseStackDifferentialVerdict) -> &'static str {
    match verdict {
        ReleaseStackDifferentialVerdict::Match => "MATCH",
        ReleaseStackDifferentialVerdict::Counterexample => "COUNTEREXAMPLE",
        ReleaseStackDifferentialVerdict::Unresolved => "UNRESOLVED",
    }
}

fn origin_name(origin: DifferentialEvidenceOrigin) -> &'static str {
    match origin {
        DifferentialEvidenceOrigin::ExecutedSoftware => "EXECUTED_SOFTWARE",
        DifferentialEvidenceOrigin::InjectedTestFixture => "INJECTED_TEST_FIXTURE",
    }
}

fn module_name(module: NoticerModuleId) -> &'static str {
    match module {
        NoticerModuleId::Aets => "AETS",
        NoticerModuleId::Atv2FramePlanner => "ATV2_FRAME_PLANNER",
        NoticerModuleId::Aplot => "APLOT",
        NoticerModuleId::Aepa => "AEPA",
        NoticerModuleId::MenfuguExecutionPlanner => "MENFUGU_EXECUTION_PLANNER",
    }
}

fn difference_name(kind: DifferentialDifferenceKind) -> &'static str {
    match kind {
        DifferentialDifferenceKind::Action => "ACTION",
        DifferentialDifferenceKind::HostCall => "HOST_CALL",
        DifferentialDifferenceKind::Trap => "TRAP",
        DifferentialDifferenceKind::Trace => "TRACE",
        DifferentialDifferenceKind::Output => "OUTPUT",
        DifferentialDifferenceKind::Profile => "PROFILE",
    }
}

fn unresolved_name(reason: DifferentialUnresolvedReason) -> &'static str {
    match reason {
        DifferentialUnresolvedReason::MissingReferenceRun => "MISSING_REFERENCE_RUN",
        DifferentialUnresolvedReason::MissingWasmiRun => "MISSING_WASMI_RUN",
        DifferentialUnresolvedReason::MissingWasmtimeRun => "MISSING_WASMTIME_RUN",
        DifferentialUnresolvedReason::EngineTimeout => "ENGINE_TIMEOUT",
        DifferentialUnresolvedReason::MalformedArtifact => "MALFORMED_ARTIFACT",
        DifferentialUnresolvedReason::ContractMismatch => "CONTRACT_MISMATCH",
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn fixture_digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}
