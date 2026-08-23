use std::collections::BTreeSet;

use quotient_forge_caqt::{artifact_digest, Digest};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{ExecutionLimits, ObservableEvent};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_menfugu_differential, MenfuguCompiledQsm, MenfuguDifferentialArtifact,
    MenfuguDifferentialEvidenceOrigin, MenfuguDifferentialVerdict, MenfuguEngineDigests,
    MenfuguPublicInput, MenfuguPublicSequence,
};

pub const MENFUGU_ADVERSARIAL_MATRIX_VERSION: &str = "noticer-menfugu-adversarial-matrix/v1";
const MATRIX_MAGIC: &[u8; 8] = b"MENMTRX1";
const MATRIX_DOMAIN: &[u8] = b"noticer-core/menfugu/adversarial-matrix/v1";
const CASE_DOMAIN: &[u8] = b"noticer-core/menfugu/adversarial-case/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const P1_UNRESOLVED: &str = "P1_MENFUGU_SEALED_ADMISSION_NOT_IMPLEMENTED";
const REQUIRED_CASES: usize = MenfuguProfileAxis::ALL.len() * MenfuguScenarioAxis::ALL.len();

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguProfileAxis {
    P0PublicQuotientOnly = 0,
    P1SealedAdmission = 1,
}

impl MenfuguProfileAxis {
    pub const ALL: [Self; 2] = [Self::P0PublicQuotientOnly, Self::P1SealedAdmission];

    #[must_use]
    pub const fn deployment_profile(self) -> DeploymentProfile {
        match self {
            Self::P0PublicQuotientOnly => DeploymentProfile::P0PublicQuotientOnly,
            Self::P1SealedAdmission => DeploymentProfile::P1SealedAdmission,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P0PublicQuotientOnly => "P0_PUBLIC_QUOTIENT_ONLY",
            Self::P1SealedAdmission => "P1_SEALED_ADMISSION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguScenarioAxis {
    ValidAction = 0,
    Cover = 1,
    Replay = 2,
    Expiry = 3,
    WrongService = 4,
    WrongPolicy = 5,
    WrongKey = 6,
    Duplicate = 7,
    Reset = 8,
    Handoff = 9,
    Deadline = 10,
    FuelBoundary = 11,
    HostCallBoundary = 12,
}

impl MenfuguScenarioAxis {
    pub const ALL: [Self; 13] = [
        Self::ValidAction,
        Self::Cover,
        Self::Replay,
        Self::Expiry,
        Self::WrongService,
        Self::WrongPolicy,
        Self::WrongKey,
        Self::Duplicate,
        Self::Reset,
        Self::Handoff,
        Self::Deadline,
        Self::FuelBoundary,
        Self::HostCallBoundary,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ValidAction => "VALID_ACTION",
            Self::Cover => "COVER",
            Self::Replay => "REPLAY",
            Self::Expiry => "EXPIRY",
            Self::WrongService => "WRONG_SERVICE",
            Self::WrongPolicy => "WRONG_POLICY",
            Self::WrongKey => "WRONG_KEY",
            Self::Duplicate => "DUPLICATE",
            Self::Reset => "RESET",
            Self::Handoff => "HANDOFF",
            Self::Deadline => "DEADLINE",
            Self::FuelBoundary => "FUEL_BOUNDARY",
            Self::HostCallBoundary => "HOST_CALL_BOUNDARY",
        }
    }

    const fn fault_class(self) -> &'static str {
        match self {
            Self::ValidAction | Self::Cover => "NONE",
            Self::Replay => "REPLAY",
            Self::Expiry => "EXPIRY",
            Self::WrongService => "WRONG_SERVICE",
            Self::WrongPolicy => "WRONG_POLICY",
            Self::WrongKey => "WRONG_KEY",
            Self::Duplicate => "DUPLICATE",
            Self::Reset | Self::Handoff => "LIFECYCLE",
            Self::Deadline => "DEADLINE",
            Self::FuelBoundary | Self::HostCallBoundary => "RESOURCE_EXHAUSTION",
        }
    }

    const fn is_resource(self) -> bool {
        matches!(self, Self::FuelBoundary | Self::HostCallBoundary)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguCaseOutcome {
    SemanticMatch,
    ResourceUnresolved,
    ProfileUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguActionClassification {
    ExactlyOnce,
    ZeroActionCoverFallback,
    ZeroActionRejected,
    ExactlyOnceDuplicateRejected,
    ZeroActionLifecycle,
    ExactlyOnceDeadlineStop,
    ResourceUnresolved,
    ProfileUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MenfuguAdversarialMatrixSeed([u8; 32]);

impl MenfuguAdversarialMatrixSeed {
    pub fn new(bytes: [u8; 32]) -> Result<Self, MenfuguAdversarialMatrixError> {
        if bytes == [0; 32] {
            return Err(MenfuguAdversarialMatrixError::ZeroSeed);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguAdversarialMatrixLimits {
    pub max_cases: usize,
    pub max_commands_per_case: usize,
}

impl Default for MenfuguAdversarialMatrixLimits {
    fn default() -> Self {
        Self {
            max_cases: REQUIRED_CASES,
            max_commands_per_case: 8,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenfuguAdversarialCase {
    profile: MenfuguProfileAxis,
    scenario: MenfuguScenarioAxis,
    sequence: MenfuguPublicSequence,
    case_id: Digest,
}

impl MenfuguAdversarialCase {
    #[must_use]
    pub const fn profile(&self) -> MenfuguProfileAxis {
        self.profile
    }

    #[must_use]
    pub const fn scenario(&self) -> MenfuguScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn sequence(&self) -> &MenfuguPublicSequence {
        &self.sequence
    }

    #[must_use]
    pub const fn case_id(&self) -> Digest {
        self.case_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenfuguAdversarialMatrix {
    seed: MenfuguAdversarialMatrixSeed,
    source_digest: Digest,
    transition_digest: Digest,
    module_digest: Digest,
    capsule_digest: Digest,
    cases: Box<[MenfuguAdversarialCase]>,
    canonical_bytes: Box<[u8]>,
    matrix_digest: Digest,
}

impl MenfuguAdversarialMatrix {
    pub fn canonical(
        compiled: &MenfuguCompiledQsm,
        seed: MenfuguAdversarialMatrixSeed,
        limits: MenfuguAdversarialMatrixLimits,
    ) -> Result<Self, MenfuguAdversarialMatrixError> {
        validate_limits(limits)?;
        let mut cases = Vec::with_capacity(REQUIRED_CASES);
        for profile in MenfuguProfileAxis::ALL {
            for scenario in MenfuguScenarioAxis::ALL {
                let sequence = scenario_sequence(compiled, scenario, limits)?;
                let case_id = case_id(compiled, seed, profile, scenario, &sequence);
                cases.push(MenfuguAdversarialCase {
                    profile,
                    scenario,
                    sequence,
                    case_id,
                });
            }
        }
        let canonical_bytes = encode_matrix(compiled, seed, &cases)?;
        let matrix_digest = artifact_digest(MATRIX_DOMAIN, &canonical_bytes);
        let matrix = Self {
            seed,
            source_digest: compiled.binding().source_digest,
            transition_digest: compiled.binding().transition_digest,
            module_digest: compiled.binding().module_digest,
            capsule_digest: compiled.binding().capsule_digest,
            cases: cases.into_boxed_slice(),
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            matrix_digest,
        };
        matrix.validate_against(compiled, limits)?;
        Ok(matrix)
    }

    #[must_use]
    pub const fn seed(&self) -> MenfuguAdversarialMatrixSeed {
        self.seed
    }

    #[must_use]
    pub fn cases(&self) -> &[MenfuguAdversarialCase] {
        &self.cases
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn matrix_digest(&self) -> Digest {
        self.matrix_digest
    }

    pub fn validate_against(
        &self,
        compiled: &MenfuguCompiledQsm,
        limits: MenfuguAdversarialMatrixLimits,
    ) -> Result<(), MenfuguAdversarialMatrixError> {
        validate_limits(limits)?;
        let binding = compiled.binding();
        if self.source_digest != binding.source_digest
            || self.transition_digest != binding.transition_digest
            || self.module_digest != binding.module_digest
            || self.capsule_digest != binding.capsule_digest
            || self.cases.len() != REQUIRED_CASES
            || self.cases.len() > limits.max_cases
        {
            return Err(MenfuguAdversarialMatrixError::MatrixBinding);
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            if !seen.insert((case.profile, case.scenario))
                || case.sequence.commands().len() > limits.max_commands_per_case
            {
                return Err(MenfuguAdversarialMatrixError::CaseCoverage);
            }
            let expected = scenario_sequence(compiled, case.scenario, limits)?;
            if case.sequence != expected
                || case.case_id
                    != case_id(
                        compiled,
                        self.seed,
                        case.profile,
                        case.scenario,
                        &case.sequence,
                    )
            {
                return Err(MenfuguAdversarialMatrixError::MatrixBinding);
            }
        }
        if seen.len() != REQUIRED_CASES {
            return Err(MenfuguAdversarialMatrixError::CaseCoverage);
        }
        let expected = encode_matrix(compiled, self.seed, &self.cases)?;
        if expected.as_slice() != self.canonical_bytes.as_ref()
            || artifact_digest(MATRIX_DOMAIN, &expected) != self.matrix_digest
        {
            return Err(MenfuguAdversarialMatrixError::MatrixBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguAdversarialCaseArtifact {
    pub case_id_sha256: String,
    pub profile_axis: String,
    pub scenario_axis: String,
    pub fault_class: String,
    pub classification: MenfuguActionClassification,
    pub outcome: MenfuguCaseOutcome,
    pub expected_action_count: Option<u32>,
    pub observed_action_count: Option<u32>,
    pub observed_frame_count: Option<u32>,
    pub observed_failure_count: Option<u32>,
    pub sequence_digest_sha256: String,
    pub verdict: MenfuguDifferentialVerdict,
    pub unresolved_reason: Option<String>,
    pub differential: Option<MenfuguDifferentialArtifact>,
}

impl MenfuguAdversarialCaseArtifact {
    pub fn validate(&self) -> Result<(), MenfuguAdversarialMatrixError> {
        if !is_sha256(&self.case_id_sha256) || !is_sha256(&self.sequence_digest_sha256) {
            return Err(MenfuguAdversarialMatrixError::ArtifactContract);
        }
        let profile = profile_from_name(&self.profile_axis)
            .ok_or(MenfuguAdversarialMatrixError::ArtifactContract)?;
        let scenario = scenario_from_name(&self.scenario_axis)
            .ok_or(MenfuguAdversarialMatrixError::ArtifactContract)?;
        if self.fault_class != scenario.fault_class()
            || self.classification != expected_classification(profile, scenario)
            || self.outcome != expected_outcome(profile, scenario)
            || self.verdict != expected_verdict(self.outcome)
        {
            return Err(MenfuguAdversarialMatrixError::Classification);
        }
        if profile == MenfuguProfileAxis::P1SealedAdmission {
            if self.differential.is_some()
                || self.expected_action_count.is_some()
                || self.observed_action_count.is_some()
                || self.observed_frame_count.is_some()
                || self.observed_failure_count.is_some()
                || self.unresolved_reason.as_deref() != Some(P1_UNRESOLVED)
            {
                return Err(MenfuguAdversarialMatrixError::ProfileDowngrade);
            }
            return Ok(());
        }

        let differential = self
            .differential
            .as_ref()
            .ok_or(MenfuguAdversarialMatrixError::ArtifactContract)?;
        differential
            .validate()
            .map_err(|error| MenfuguAdversarialMatrixError::Differential(error.to_string()))?;
        if differential.evidence_origin != MenfuguDifferentialEvidenceOrigin::ExecutedSoftware
            || differential.injection_label.is_some()
            || differential.verdict != self.verdict
            || differential.sequence_digest_sha256 != self.sequence_digest_sha256
        {
            return Err(MenfuguAdversarialMatrixError::ArtifactContract);
        }
        if scenario.is_resource() {
            if self.unresolved_reason.as_deref() != Some("RESOURCE_BOUND")
                || self.expected_action_count.is_some()
            {
                return Err(MenfuguAdversarialMatrixError::ResourceConflation);
            }
        } else {
            let expected =
                expected_counts(scenario).ok_or(MenfuguAdversarialMatrixError::Classification)?;
            if self.unresolved_reason.is_some()
                || self.expected_action_count != Some(expected.actions)
                || self.observed_action_count != Some(expected.actions)
                || self.observed_frame_count != Some(expected.frames)
                || self.observed_failure_count != Some(expected.failures)
            {
                return Err(MenfuguAdversarialMatrixError::ActionCount);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguAdversarialExecutionArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub seed_sha256: String,
    pub matrix_digest_sha256: String,
    pub source_digest_sha256: String,
    pub transition_digest_sha256: String,
    pub module_digest_sha256: String,
    pub capsule_digest_sha256: String,
    pub hardware_status: String,
    pub verdict: MenfuguDifferentialVerdict,
    pub match_cases: u32,
    pub counterexample_cases: u32,
    pub unresolved_cases: u32,
    pub cases: Vec<MenfuguAdversarialCaseArtifact>,
}

impl MenfuguAdversarialExecutionArtifact {
    pub fn validate(&self) -> Result<(), MenfuguAdversarialMatrixError> {
        if self.schema_version != MENFUGU_ADVERSARIAL_MATRIX_VERSION
            || self.evaluator_version != MENFUGU_ADVERSARIAL_MATRIX_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.seed_sha256)
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.source_digest_sha256)
            || !is_sha256(&self.transition_digest_sha256)
            || !is_sha256(&self.module_digest_sha256)
            || !is_sha256(&self.capsule_digest_sha256)
            || self.cases.len() != REQUIRED_CASES
        {
            return Err(MenfuguAdversarialMatrixError::ArtifactContract);
        }
        let mut order = Vec::with_capacity(self.cases.len());
        let mut counts = [0_u32; 3];
        for case in &self.cases {
            case.validate()?;
            let profile = profile_from_name(&case.profile_axis)
                .ok_or(MenfuguAdversarialMatrixError::ArtifactContract)?;
            let scenario = scenario_from_name(&case.scenario_axis)
                .ok_or(MenfuguAdversarialMatrixError::ArtifactContract)?;
            order.push((profile, scenario));
            match case.verdict {
                MenfuguDifferentialVerdict::Match => counts[0] += 1,
                MenfuguDifferentialVerdict::Counterexample => counts[1] += 1,
                MenfuguDifferentialVerdict::Unresolved => counts[2] += 1,
            }
        }
        if !order.windows(2).all(|pair| pair[0] < pair[1])
            || self.match_cases != counts[0]
            || self.counterexample_cases != counts[1]
            || self.unresolved_cases != counts[2]
            || self.verdict != aggregate_counts(counts)
        {
            return Err(MenfuguAdversarialMatrixError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, MenfuguAdversarialMatrixError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| MenfuguAdversarialMatrixError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, MenfuguAdversarialMatrixError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_menfugu_adversarial_matrix(
    compiled: &MenfuguCompiledQsm,
    matrix: &MenfuguAdversarialMatrix,
    limits: MenfuguAdversarialMatrixLimits,
    engine_digests: &MenfuguEngineDigests,
) -> Result<MenfuguAdversarialExecutionArtifact, MenfuguAdversarialMatrixError> {
    matrix.validate_against(compiled, limits)?;
    let cases = matrix
        .cases()
        .iter()
        .map(|case| evaluate_case(compiled, case, engine_digests))
        .collect::<Result<Vec<_>, _>>()?;
    build_execution_artifact(compiled, matrix, cases)
}

pub fn verify_menfugu_adversarial_execution(
    artifact: &MenfuguAdversarialExecutionArtifact,
    compiled: &MenfuguCompiledQsm,
    matrix: &MenfuguAdversarialMatrix,
    limits: MenfuguAdversarialMatrixLimits,
    engine_digests: &MenfuguEngineDigests,
) -> Result<(), MenfuguAdversarialMatrixError> {
    artifact.validate()?;
    let recomputed = evaluate_menfugu_adversarial_matrix(compiled, matrix, limits, engine_digests)?;
    if &recomputed != artifact || recomputed.canonical_json()? != artifact.canonical_json()? {
        return Err(MenfuguAdversarialMatrixError::RecomputationMismatch);
    }
    Ok(())
}

fn evaluate_case(
    compiled: &MenfuguCompiledQsm,
    case: &MenfuguAdversarialCase,
    engine_digests: &MenfuguEngineDigests,
) -> Result<MenfuguAdversarialCaseArtifact, MenfuguAdversarialMatrixError> {
    let profile = case.profile;
    let scenario = case.scenario;
    if profile == MenfuguProfileAxis::P1SealedAdmission {
        let artifact = MenfuguAdversarialCaseArtifact {
            case_id_sha256: hex(case.case_id.as_bytes()),
            profile_axis: profile.name().to_owned(),
            scenario_axis: scenario.name().to_owned(),
            fault_class: scenario.fault_class().to_owned(),
            classification: MenfuguActionClassification::ProfileUnresolved,
            outcome: MenfuguCaseOutcome::ProfileUnresolved,
            expected_action_count: None,
            observed_action_count: None,
            observed_frame_count: None,
            observed_failure_count: None,
            sequence_digest_sha256: hex(case.sequence.digest().as_bytes()),
            verdict: MenfuguDifferentialVerdict::Unresolved,
            unresolved_reason: Some(P1_UNRESOLVED.to_owned()),
            differential: None,
        };
        artifact.validate()?;
        return Ok(artifact);
    }

    let differential = evaluate_menfugu_differential(compiled, &case.sequence, engine_digests)
        .map_err(|error| MenfuguAdversarialMatrixError::Differential(error.to_string()))?;
    let outcome = expected_outcome(profile, scenario);
    if differential.verdict != expected_verdict(outcome) {
        return Err(MenfuguAdversarialMatrixError::UnexpectedVerdict);
    }
    let counts = observed_counts(&differential)?;
    let expected = expected_counts(scenario);
    let artifact = MenfuguAdversarialCaseArtifact {
        case_id_sha256: hex(case.case_id.as_bytes()),
        profile_axis: profile.name().to_owned(),
        scenario_axis: scenario.name().to_owned(),
        fault_class: scenario.fault_class().to_owned(),
        classification: expected_classification(profile, scenario),
        outcome,
        expected_action_count: expected.map(|value| value.actions),
        observed_action_count: Some(counts.actions),
        observed_frame_count: Some(counts.frames),
        observed_failure_count: Some(counts.failures),
        sequence_digest_sha256: hex(case.sequence.digest().as_bytes()),
        verdict: differential.verdict,
        unresolved_reason: scenario.is_resource().then(|| "RESOURCE_BOUND".to_owned()),
        differential: Some(differential),
    };
    artifact.validate()?;
    Ok(artifact)
}

fn build_execution_artifact(
    compiled: &MenfuguCompiledQsm,
    matrix: &MenfuguAdversarialMatrix,
    cases: Vec<MenfuguAdversarialCaseArtifact>,
) -> Result<MenfuguAdversarialExecutionArtifact, MenfuguAdversarialMatrixError> {
    let mut counts = [0_u32; 3];
    for case in &cases {
        match case.verdict {
            MenfuguDifferentialVerdict::Match => counts[0] += 1,
            MenfuguDifferentialVerdict::Counterexample => counts[1] += 1,
            MenfuguDifferentialVerdict::Unresolved => counts[2] += 1,
        }
    }
    let binding = compiled.binding();
    let artifact = MenfuguAdversarialExecutionArtifact {
        schema_version: MENFUGU_ADVERSARIAL_MATRIX_VERSION.to_owned(),
        evaluator_version: MENFUGU_ADVERSARIAL_MATRIX_VERSION.to_owned(),
        seed_sha256: sha256_hex(&matrix.seed.as_bytes()),
        matrix_digest_sha256: hex(matrix.matrix_digest.as_bytes()),
        source_digest_sha256: hex(binding.source_digest.as_bytes()),
        transition_digest_sha256: hex(binding.transition_digest.as_bytes()),
        module_digest_sha256: hex(binding.module_digest.as_bytes()),
        capsule_digest_sha256: hex(binding.capsule_digest.as_bytes()),
        hardware_status: HARDWARE_STATUS.to_owned(),
        verdict: aggregate_counts(counts),
        match_cases: counts[0],
        counterexample_cases: counts[1],
        unresolved_cases: counts[2],
        cases,
    };
    artifact.validate()?;
    Ok(artifact)
}

#[derive(Clone, Copy)]
struct Counts {
    actions: u32,
    frames: u32,
    failures: u32,
}

fn observed_counts(
    differential: &MenfuguDifferentialArtifact,
) -> Result<Counts, MenfuguAdversarialMatrixError> {
    let run = differential
        .source_reference
        .as_ref()
        .unwrap_or(&differential.oracle.reference);
    let mut counts = Counts {
        actions: 0,
        frames: 0,
        failures: 0,
    };
    for event in &run.trace {
        match event {
            ObservableEvent::EmitAction { .. } => counts.actions += 1,
            ObservableEvent::EmitFrame { .. } => counts.frames += 1,
            ObservableEvent::PublicFailure { .. } => counts.failures += 1,
            _ => {}
        }
    }
    Ok(counts)
}

const fn expected_counts(scenario: MenfuguScenarioAxis) -> Option<Counts> {
    match scenario {
        MenfuguScenarioAxis::ValidAction => Some(Counts {
            actions: 1,
            frames: 1,
            failures: 0,
        }),
        MenfuguScenarioAxis::Cover => Some(Counts {
            actions: 0,
            frames: 1,
            failures: 0,
        }),
        MenfuguScenarioAxis::Replay
        | MenfuguScenarioAxis::Expiry
        | MenfuguScenarioAxis::WrongService
        | MenfuguScenarioAxis::WrongPolicy
        | MenfuguScenarioAxis::WrongKey => Some(Counts {
            actions: 0,
            frames: 1,
            failures: 1,
        }),
        MenfuguScenarioAxis::Duplicate => Some(Counts {
            actions: 1,
            frames: 2,
            failures: 1,
        }),
        MenfuguScenarioAxis::Reset | MenfuguScenarioAxis::Handoff => Some(Counts {
            actions: 0,
            frames: 1,
            failures: 0,
        }),
        MenfuguScenarioAxis::Deadline => Some(Counts {
            actions: 1,
            frames: 2,
            failures: 0,
        }),
        MenfuguScenarioAxis::FuelBoundary | MenfuguScenarioAxis::HostCallBoundary => None,
    }
}

const fn expected_classification(
    profile: MenfuguProfileAxis,
    scenario: MenfuguScenarioAxis,
) -> MenfuguActionClassification {
    if matches!(profile, MenfuguProfileAxis::P1SealedAdmission) {
        return MenfuguActionClassification::ProfileUnresolved;
    }
    match scenario {
        MenfuguScenarioAxis::ValidAction => MenfuguActionClassification::ExactlyOnce,
        MenfuguScenarioAxis::Cover => MenfuguActionClassification::ZeroActionCoverFallback,
        MenfuguScenarioAxis::Replay
        | MenfuguScenarioAxis::Expiry
        | MenfuguScenarioAxis::WrongService
        | MenfuguScenarioAxis::WrongPolicy
        | MenfuguScenarioAxis::WrongKey => MenfuguActionClassification::ZeroActionRejected,
        MenfuguScenarioAxis::Duplicate => MenfuguActionClassification::ExactlyOnceDuplicateRejected,
        MenfuguScenarioAxis::Reset | MenfuguScenarioAxis::Handoff => {
            MenfuguActionClassification::ZeroActionLifecycle
        }
        MenfuguScenarioAxis::Deadline => MenfuguActionClassification::ExactlyOnceDeadlineStop,
        MenfuguScenarioAxis::FuelBoundary | MenfuguScenarioAxis::HostCallBoundary => {
            MenfuguActionClassification::ResourceUnresolved
        }
    }
}

const fn expected_outcome(
    profile: MenfuguProfileAxis,
    scenario: MenfuguScenarioAxis,
) -> MenfuguCaseOutcome {
    if matches!(profile, MenfuguProfileAxis::P1SealedAdmission) {
        MenfuguCaseOutcome::ProfileUnresolved
    } else if scenario.is_resource() {
        MenfuguCaseOutcome::ResourceUnresolved
    } else {
        MenfuguCaseOutcome::SemanticMatch
    }
}

const fn expected_verdict(outcome: MenfuguCaseOutcome) -> MenfuguDifferentialVerdict {
    match outcome {
        MenfuguCaseOutcome::SemanticMatch => MenfuguDifferentialVerdict::Match,
        MenfuguCaseOutcome::ResourceUnresolved | MenfuguCaseOutcome::ProfileUnresolved => {
            MenfuguDifferentialVerdict::Unresolved
        }
    }
}

fn scenario_sequence(
    compiled: &MenfuguCompiledQsm,
    scenario: MenfuguScenarioAxis,
    limits: MenfuguAdversarialMatrixLimits,
) -> Result<MenfuguPublicSequence, MenfuguAdversarialMatrixError> {
    let (mut commands, execution_limits) = scenario_commands(scenario);
    for command in &mut commands {
        if command.service_alias != 0 {
            command.service_alias = compiled.service_code().qsm_alias;
        }
    }
    MenfuguPublicSequence::new(
        compiled,
        commands,
        execution_limits,
        limits.max_commands_per_case,
    )
    .map_err(|error| MenfuguAdversarialMatrixError::Sequence(error.to_string()))
}

fn scenario_commands(scenario: MenfuguScenarioAxis) -> (Vec<ContextCommand>, ExecutionLimits) {
    let mut limits = nominal_limits();
    let commands = match scenario {
        MenfuguScenarioAxis::ValidAction => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 0),
            stop(),
        ],
        MenfuguScenarioAxis::Cover => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::Cover, 0),
            stop(),
        ],
        MenfuguScenarioAxis::Replay => vec![
            input(
                ContextFamily::CrossServiceReplay,
                MenfuguPublicInput::ReplayRejected,
                0,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::Expiry => vec![
            input(
                ContextFamily::Deadline,
                MenfuguPublicInput::ExpiredRejected,
                0,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::WrongService => vec![
            input(
                ContextFamily::ServiceCollusion,
                MenfuguPublicInput::WrongServiceRejected,
                0,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::WrongPolicy => vec![
            input(
                ContextFamily::ServiceCollusion,
                MenfuguPublicInput::WrongPolicyRejected,
                0,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::WrongKey => vec![
            input(
                ContextFamily::ServiceCollusion,
                MenfuguPublicInput::WrongKeyRejected,
                0,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::Duplicate => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 0),
            input(
                ContextFamily::ServiceCollusion,
                MenfuguPublicInput::DuplicateTransport,
                1,
            ),
            stop(),
        ],
        MenfuguScenarioAxis::Reset => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::Cover, 0),
            lifecycle(ContextFamily::Reset),
            stop(),
        ],
        MenfuguScenarioAxis::Handoff => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::Cover, 0),
            lifecycle(ContextFamily::Handoff),
            stop(),
        ],
        MenfuguScenarioAxis::Deadline => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 0),
            input(ContextFamily::Deadline, MenfuguPublicInput::Deadline, 1),
            stop(),
        ],
        MenfuguScenarioAxis::FuelBoundary | MenfuguScenarioAxis::HostCallBoundary => vec![
            input(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 0),
            stop(),
        ],
    };
    match scenario {
        MenfuguScenarioAxis::FuelBoundary => limits.fuel = 1,
        MenfuguScenarioAxis::HostCallBoundary => limits.max_host_calls = 1,
        _ => {}
    }
    (commands, limits)
}

fn input(family: ContextFamily, input: MenfuguPublicInput, public_slot: u64) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias: 23,
        public_slot,
        fault: input as u8,
        payload_tag: 0,
    }
}

fn lifecycle(family: ContextFamily) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias: 0,
        public_slot: 0,
        fault: 0,
        payload_tag: 0,
    }
}

fn stop() -> ContextCommand {
    lifecycle(ContextFamily::Stop)
}

const fn nominal_limits() -> ExecutionLimits {
    ExecutionLimits {
        fuel: 1_000_000,
        max_memory_pages: 2,
        max_host_calls: 32,
        timeout_ms: 2_000,
    }
}

fn case_id(
    compiled: &MenfuguCompiledQsm,
    seed: MenfuguAdversarialMatrixSeed,
    profile: MenfuguProfileAxis,
    scenario: MenfuguScenarioAxis,
    sequence: &MenfuguPublicSequence,
) -> Digest {
    let binding = compiled.binding();
    let mut bytes = Vec::with_capacity(196);
    bytes.extend_from_slice(&seed.as_bytes());
    bytes.extend_from_slice(binding.source_digest.as_bytes());
    bytes.extend_from_slice(binding.transition_digest.as_bytes());
    bytes.extend_from_slice(binding.module_digest.as_bytes());
    bytes.extend_from_slice(binding.capsule_digest.as_bytes());
    bytes.push(profile as u8);
    bytes.push(scenario as u8);
    bytes.extend_from_slice(sequence.digest().as_bytes());
    artifact_digest(CASE_DOMAIN, &bytes)
}

fn encode_matrix(
    compiled: &MenfuguCompiledQsm,
    seed: MenfuguAdversarialMatrixSeed,
    cases: &[MenfuguAdversarialCase],
) -> Result<Vec<u8>, MenfuguAdversarialMatrixError> {
    let binding = compiled.binding();
    let mut bytes = Vec::with_capacity(256 + cases.len() * 66);
    bytes.extend_from_slice(MATRIX_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&seed.as_bytes());
    bytes.extend_from_slice(binding.source_digest.as_bytes());
    bytes.extend_from_slice(binding.transition_digest.as_bytes());
    bytes.extend_from_slice(binding.module_digest.as_bytes());
    bytes.extend_from_slice(binding.capsule_digest.as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(cases.len())
            .map_err(|_| MenfuguAdversarialMatrixError::Arithmetic)?
            .to_le_bytes(),
    );
    for case in cases {
        bytes.push(case.profile as u8);
        bytes.push(case.scenario as u8);
        bytes.extend_from_slice(case.case_id.as_bytes());
        bytes.extend_from_slice(case.sequence.digest().as_bytes());
    }
    Ok(bytes)
}

fn validate_limits(
    limits: MenfuguAdversarialMatrixLimits,
) -> Result<(), MenfuguAdversarialMatrixError> {
    if limits.max_cases < REQUIRED_CASES || limits.max_commands_per_case == 0 {
        return Err(MenfuguAdversarialMatrixError::InvalidLimits);
    }
    Ok(())
}

fn profile_from_name(name: &str) -> Option<MenfuguProfileAxis> {
    MenfuguProfileAxis::ALL
        .into_iter()
        .find(|profile| profile.name() == name)
}

fn scenario_from_name(name: &str) -> Option<MenfuguScenarioAxis> {
    MenfuguScenarioAxis::ALL
        .into_iter()
        .find(|scenario| scenario.name() == name)
}

const fn aggregate_counts(counts: [u32; 3]) -> MenfuguDifferentialVerdict {
    if counts[2] != 0 {
        MenfuguDifferentialVerdict::Unresolved
    } else if counts[1] != 0 {
        MenfuguDifferentialVerdict::Counterexample
    } else {
        MenfuguDifferentialVerdict::Match
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MenfuguAdversarialMatrixError {
    #[error("matrix seed must be nonzero")]
    ZeroSeed,
    #[error("matrix limits cannot cover the canonical matrix")]
    InvalidLimits,
    #[error("matrix case coverage is not canonical")]
    CaseCoverage,
    #[error("matrix or case binding mismatch")]
    MatrixBinding,
    #[error("public sequence failed: {0}")]
    Sequence(String),
    #[error("differential execution failed: {0}")]
    Differential(String),
    #[error("case verdict did not match its declared scenario")]
    UnexpectedVerdict,
    #[error("action count violated the scenario contract")]
    ActionCount,
    #[error("case classification violated the scenario contract")]
    Classification,
    #[error("P1 case was implicitly downgraded to P0")]
    ProfileDowngrade,
    #[error("semantic fault and resource exhaustion were conflated")]
    ResourceConflation,
    #[error("adversarial execution artifact violated its contract")]
    ArtifactContract,
    #[error("adversarial execution artifact serialization failed: {0}")]
    Serialization(String),
    #[error("adversarial execution recomputation mismatch")]
    RecomputationMismatch,
    #[error("adversarial matrix arithmetic overflow")]
    Arithmetic,
}
