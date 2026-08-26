use sha2::{Digest as _, Sha256};
use std::fmt;

use crate::NoticerModuleId;

pub const RELEASE_STACK_DIFFERENTIAL_SCHEMA: &str = "noticer.release_stack.differential.v1";
const DOMAIN: &[u8] = b"NOTICER_RELEASE_STACK_DIFFERENTIAL_V1";
const MODULE_COUNT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStackDifferentialVerdict {
    Match,
    Counterexample,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialEvidenceOrigin {
    ExecutedSoftware,
    InjectedTestFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialDifferenceKind {
    Action,
    HostCall,
    Trap,
    Trace,
    Output,
    Profile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DifferentialDifference {
    pub kind: DifferentialDifferenceKind,
    pub step_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialUnresolvedReason {
    MissingReferenceRun,
    MissingWasmiRun,
    MissingWasmtimeRun,
    EngineTimeout,
    MalformedArtifact,
    ContractMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineArtifactDigests {
    pub reference_sha256: [u8; 32],
    pub wasmi_sha256: [u8; 32],
    pub wasmtime_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDifferentialEvidence {
    pub module: NoticerModuleId,
    pub module_artifact_sha256: [u8; 32],
    pub engines: EngineArtifactDigests,
    pub verdict: ReleaseStackDifferentialVerdict,
    pub first_difference: Option<DifferentialDifference>,
    pub unresolved_reason: Option<DifferentialUnresolvedReason>,
    pub evidence_origin: DifferentialEvidenceOrigin,
}

impl ModuleDifferentialEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn from_existing_artifact(
        module: NoticerModuleId,
        module_artifact_sha256: [u8; 32],
        engines: EngineArtifactDigests,
        verdict: ReleaseStackDifferentialVerdict,
        first_difference: Option<DifferentialDifference>,
        unresolved_reason: Option<DifferentialUnresolvedReason>,
        evidence_origin: DifferentialEvidenceOrigin,
    ) -> Self {
        Self {
            module,
            module_artifact_sha256,
            engines,
            verdict,
            first_difference,
            unresolved_reason,
            evidence_origin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseStackDifferentialBindings {
    pub manifest_sha256: [u8; 32],
    pub composition_contract_sha256: [u8; 32],
    pub path_contract_sha256: [u8; 32],
    pub profile_contract_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseStackDifferentialArtifact {
    pub schema: &'static str,
    pub bindings: ReleaseStackDifferentialBindings,
    pub modules: [ModuleDifferentialEvidence; MODULE_COUNT],
    pub verdict: ReleaseStackDifferentialVerdict,
    pub first_counterexample_module: Option<NoticerModuleId>,
    pub first_unresolved_module: Option<NoticerModuleId>,
    pub evidence_origin: DifferentialEvidenceOrigin,
    pub artifact_sha256: [u8; 32],
}

impl ReleaseStackDifferentialArtifact {
    pub fn evaluate(
        bindings: ReleaseStackDifferentialBindings,
        modules: [ModuleDifferentialEvidence; MODULE_COUNT],
    ) -> Result<Self, ReleaseStackDifferentialError> {
        validate_bindings(&bindings)?;
        for (index, evidence) in modules.iter().enumerate() {
            let expected = NoticerModuleId::ALL[index];
            if evidence.module != expected {
                return Err(ReleaseStackDifferentialError::UnexpectedModule {
                    index,
                    expected,
                    actual: evidence.module,
                });
            }
            validate_module(evidence)?;
        }

        let first_counterexample_module = modules
            .iter()
            .find(|evidence| evidence.verdict == ReleaseStackDifferentialVerdict::Counterexample)
            .map(|evidence| evidence.module);
        let first_unresolved_module = modules
            .iter()
            .find(|evidence| evidence.verdict == ReleaseStackDifferentialVerdict::Unresolved)
            .map(|evidence| evidence.module);
        let verdict = if first_counterexample_module.is_some() {
            ReleaseStackDifferentialVerdict::Counterexample
        } else if first_unresolved_module.is_some() {
            ReleaseStackDifferentialVerdict::Unresolved
        } else {
            ReleaseStackDifferentialVerdict::Match
        };
        let evidence_origin = if modules.iter().any(|evidence| {
            evidence.evidence_origin == DifferentialEvidenceOrigin::InjectedTestFixture
        }) {
            DifferentialEvidenceOrigin::InjectedTestFixture
        } else {
            DifferentialEvidenceOrigin::ExecutedSoftware
        };

        let mut artifact = Self {
            schema: RELEASE_STACK_DIFFERENTIAL_SCHEMA,
            bindings,
            modules,
            verdict,
            first_counterexample_module,
            first_unresolved_module,
            evidence_origin,
            artifact_sha256: [0; 32],
        };
        artifact.artifact_sha256 = artifact.recomputed_sha256();
        Ok(artifact)
    }

    pub fn verify_complete_recomputation(&self) -> Result<(), ReleaseStackDifferentialError> {
        let recomputed = Self::evaluate(self.bindings, self.modules.clone())?;
        if self != &recomputed {
            return Err(ReleaseStackDifferentialError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn recomputed_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.bindings.manifest_sha256);
        hasher.update(self.bindings.composition_contract_sha256);
        hasher.update(self.bindings.path_contract_sha256);
        hasher.update(self.bindings.profile_contract_sha256);
        for evidence in &self.modules {
            hasher.update([module_code(&evidence.module)]);
            hasher.update(evidence.module_artifact_sha256);
            hasher.update(evidence.engines.reference_sha256);
            hasher.update(evidence.engines.wasmi_sha256);
            hasher.update(evidence.engines.wasmtime_sha256);
            hasher.update([verdict_code(evidence.verdict)]);
            encode_difference(&mut hasher, evidence.first_difference);
            hasher.update([unresolved_code(evidence.unresolved_reason)]);
            hasher.update([origin_code(evidence.evidence_origin)]);
        }
        hasher.update([verdict_code(self.verdict)]);
        hasher.update([optional_module_code(
            self.first_counterexample_module.as_ref(),
        )]);
        hasher.update([optional_module_code(self.first_unresolved_module.as_ref())]);
        hasher.update([origin_code(self.evidence_origin)]);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseStackDifferentialError {
    ZeroBinding(&'static str),
    UnexpectedModule {
        index: usize,
        expected: NoticerModuleId,
        actual: NoticerModuleId,
    },
    ZeroModuleDigest(NoticerModuleId),
    ZeroEngineDigest {
        module: NoticerModuleId,
        engine: &'static str,
    },
    InvalidVerdictEvidence(NoticerModuleId),
    ArtifactMismatch,
}

impl fmt::Display for ReleaseStackDifferentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBinding(name) => write!(formatter, "zero release-stack binding: {name}"),
            Self::UnexpectedModule { index, .. } => {
                write!(formatter, "unexpected module at canonical stage {index}")
            }
            Self::ZeroModuleDigest(_) => write!(formatter, "zero module artifact digest"),
            Self::ZeroEngineDigest { engine, .. } => {
                write!(formatter, "zero {engine} execution artifact digest")
            }
            Self::InvalidVerdictEvidence(_) => {
                write!(formatter, "verdict and evidence fields are inconsistent")
            }
            Self::ArtifactMismatch => write!(formatter, "artifact failed complete recomputation"),
        }
    }
}

impl std::error::Error for ReleaseStackDifferentialError {}

fn validate_bindings(
    bindings: &ReleaseStackDifferentialBindings,
) -> Result<(), ReleaseStackDifferentialError> {
    for (name, digest) in [
        ("manifest", bindings.manifest_sha256),
        ("composition_contract", bindings.composition_contract_sha256),
        ("path_contract", bindings.path_contract_sha256),
        ("profile_contract", bindings.profile_contract_sha256),
    ] {
        if digest == [0; 32] {
            return Err(ReleaseStackDifferentialError::ZeroBinding(name));
        }
    }
    Ok(())
}

fn validate_module(
    evidence: &ModuleDifferentialEvidence,
) -> Result<(), ReleaseStackDifferentialError> {
    if evidence.module_artifact_sha256 == [0; 32] {
        return Err(ReleaseStackDifferentialError::ZeroModuleDigest(
            evidence.module,
        ));
    }
    for (engine, digest) in [
        ("reference", evidence.engines.reference_sha256),
        ("wasmi", evidence.engines.wasmi_sha256),
        ("wasmtime", evidence.engines.wasmtime_sha256),
    ] {
        if digest == [0; 32] {
            return Err(ReleaseStackDifferentialError::ZeroEngineDigest {
                module: evidence.module,
                engine,
            });
        }
    }
    let consistent = match evidence.verdict {
        ReleaseStackDifferentialVerdict::Match => {
            evidence.first_difference.is_none() && evidence.unresolved_reason.is_none()
        }
        ReleaseStackDifferentialVerdict::Counterexample => {
            evidence.first_difference.is_some() && evidence.unresolved_reason.is_none()
        }
        ReleaseStackDifferentialVerdict::Unresolved => {
            evidence.first_difference.is_none() && evidence.unresolved_reason.is_some()
        }
    };
    if !consistent {
        return Err(ReleaseStackDifferentialError::InvalidVerdictEvidence(
            evidence.module,
        ));
    }
    Ok(())
}

fn encode_difference(hasher: &mut Sha256, difference: Option<DifferentialDifference>) {
    match difference {
        Some(difference) => {
            hasher.update([1, difference_code(difference.kind)]);
            hasher.update(difference.step_index.to_be_bytes());
        }
        None => hasher.update([0, 0, 0, 0, 0, 0]),
    }
}

fn module_code(module: &NoticerModuleId) -> u8 {
    match module {
        NoticerModuleId::Aets => 1,
        NoticerModuleId::Atv2FramePlanner => 2,
        NoticerModuleId::Aplot => 3,
        NoticerModuleId::Aepa => 4,
        NoticerModuleId::MenfuguExecutionPlanner => 5,
    }
}

fn optional_module_code(module: Option<&NoticerModuleId>) -> u8 {
    module.map_or(0, module_code)
}

fn verdict_code(verdict: ReleaseStackDifferentialVerdict) -> u8 {
    match verdict {
        ReleaseStackDifferentialVerdict::Match => 1,
        ReleaseStackDifferentialVerdict::Counterexample => 2,
        ReleaseStackDifferentialVerdict::Unresolved => 3,
    }
}

fn origin_code(origin: DifferentialEvidenceOrigin) -> u8 {
    match origin {
        DifferentialEvidenceOrigin::ExecutedSoftware => 1,
        DifferentialEvidenceOrigin::InjectedTestFixture => 2,
    }
}

fn difference_code(kind: DifferentialDifferenceKind) -> u8 {
    match kind {
        DifferentialDifferenceKind::Action => 1,
        DifferentialDifferenceKind::HostCall => 2,
        DifferentialDifferenceKind::Trap => 3,
        DifferentialDifferenceKind::Trace => 4,
        DifferentialDifferenceKind::Output => 5,
        DifferentialDifferenceKind::Profile => 6,
    }
}

fn unresolved_code(reason: Option<DifferentialUnresolvedReason>) -> u8 {
    match reason {
        None => 0,
        Some(DifferentialUnresolvedReason::MissingReferenceRun) => 1,
        Some(DifferentialUnresolvedReason::MissingWasmiRun) => 2,
        Some(DifferentialUnresolvedReason::MissingWasmtimeRun) => 3,
        Some(DifferentialUnresolvedReason::EngineTimeout) => 4,
        Some(DifferentialUnresolvedReason::MalformedArtifact) => 5,
        Some(DifferentialUnresolvedReason::ContractMismatch) => 6,
    }
}
