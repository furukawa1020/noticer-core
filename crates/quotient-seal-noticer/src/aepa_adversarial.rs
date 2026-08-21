use std::collections::BTreeSet;

use quotient_forge_caqt::artifact_digest;
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    DifferentialOracle, DifferentialVerdict, ExecutionLimits, ObservableEvent,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    authorize_aepa_profile, build_aepa_injected_fixture_artifact, evaluate_aepa_differential,
    AepaCompiledQsm, AepaDifferentialArtifact, AepaDifferentialEvidenceOrigin,
    AepaDifferentialVerdict, AepaEngineDigests, AepaK7Binding, AepaP1Revalidation, AepaPublicInput,
    AepaPublicSequence, AepaPublicSourceArtifact, Digest, NoticerQsmManifest,
};

pub const AEPA_ADVERSARIAL_MATRIX_VERSION: &str = "noticer-aepa-adversarial-matrix/v1";
const MATRIX_MAGIC: &[u8; 8] = b"AEPAAMX1";
const MATRIX_DOMAIN: &[u8] = b"noticer-core/aepa/adversarial-matrix/v1";
const CASE_DOMAIN: &[u8] = b"noticer-core/aepa/adversarial-case/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const TARGET_ONLY_LABEL: &str = "TARGET_ONLY_ADMISSION_TEST_INSTRUMENTATION";
const REQUIRED_CASES: usize = AepaProfileAxis::ALL.len() * AepaScenarioAxis::ALL.len();

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaProfileAxis {
    P0PublicQuotientOnly = 0,
    P1SealedAdmission = 1,
}

impl AepaProfileAxis {
    pub const ALL: [Self; 2] = [Self::P0PublicQuotientOnly, Self::P1SealedAdmission];

    #[must_use]
    pub const fn deployment_profile(self) -> DeploymentProfile {
        match self {
            Self::P0PublicQuotientOnly => DeploymentProfile::P0PublicQuotientOnly,
            Self::P1SealedAdmission => DeploymentProfile::P1SealedAdmission,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::P0PublicQuotientOnly => "P0_PUBLIC_QUOTIENT_ONLY",
            Self::P1SealedAdmission => "P1_SEALED_ADMISSION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaScenarioAxis {
    Normal = 0,
    Replay = 1,
    Expiry = 2,
    Downgrade = 3,
    WrongBinding = 4,
    Duplicate = 5,
    TargetOnlyAdmission = 6,
    FuelBoundary = 7,
    HostCallBoundary = 8,
}

impl AepaScenarioAxis {
    pub const ALL: [Self; 9] = [
        Self::Normal,
        Self::Replay,
        Self::Expiry,
        Self::Downgrade,
        Self::WrongBinding,
        Self::Duplicate,
        Self::TargetOnlyAdmission,
        Self::FuelBoundary,
        Self::HostCallBoundary,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Replay => "REPLAY",
            Self::Expiry => "EXPIRY",
            Self::Downgrade => "DOWNGRADE",
            Self::WrongBinding => "WRONG_BINDING",
            Self::Duplicate => "DUPLICATE",
            Self::TargetOnlyAdmission => "TARGET_ONLY_ADMISSION",
            Self::FuelBoundary => "FUEL_BOUNDARY",
            Self::HostCallBoundary => "HOST_CALL_BOUNDARY",
        }
    }

    const fn fault_class(self) -> &'static str {
        match self {
            Self::Normal | Self::TargetOnlyAdmission => "NONE",
            Self::Replay => "REPLAY",
            Self::Expiry => "EXPIRY",
            Self::Downgrade => "DOWNGRADE",
            Self::WrongBinding => "WRONG_BINDING",
            Self::Duplicate => "DUPLICATE_PUBLIC_STEP",
            Self::FuelBoundary | Self::HostCallBoundary => "RESOURCE_EXHAUSTION",
        }
    }

    const fn expected_outcome(self) -> AepaCaseOutcome {
        match self {
            Self::TargetOnlyAdmission => AepaCaseOutcome::InjectedCounterexample,
            Self::FuelBoundary | Self::HostCallBoundary => AepaCaseOutcome::ResourceUnresolved,
            _ => AepaCaseOutcome::SemanticMatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaCaseOutcome {
    SemanticMatch,
    InjectedCounterexample,
    ResourceUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AepaAdversarialMatrixSeed([u8; 32]);

impl AepaAdversarialMatrixSeed {
    pub fn new(bytes: [u8; 32]) -> Result<Self, AepaAdversarialMatrixError> {
        if bytes == [0; 32] {
            return Err(AepaAdversarialMatrixError::ZeroSeed);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaAdversarialMatrixLimits {
    pub max_cases: usize,
    pub max_commands_per_case: usize,
}

impl Default for AepaAdversarialMatrixLimits {
    fn default() -> Self {
        Self {
            max_cases: REQUIRED_CASES,
            max_commands_per_case: 32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaAdversarialCaseSpec {
    profile: AepaProfileAxis,
    scenario: AepaScenarioAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AepaAdversarialCaseSpec {
    #[must_use]
    pub fn new(
        profile: AepaProfileAxis,
        scenario: AepaScenarioAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            profile,
            scenario,
            commands,
            limits,
        }
    }

    #[must_use]
    pub const fn profile(&self) -> AepaProfileAxis {
        self.profile
    }

    #[must_use]
    pub const fn scenario(&self) -> AepaScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub fn commands(&self) -> &[ContextCommand] {
        &self.commands
    }

    #[must_use]
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaAdversarialCase {
    profile: AepaProfileAxis,
    scenario: AepaScenarioAxis,
    sequence: AepaPublicSequence,
    case_id: Digest,
}

impl AepaAdversarialCase {
    #[must_use]
    pub const fn profile(&self) -> AepaProfileAxis {
        self.profile
    }

    #[must_use]
    pub const fn scenario(&self) -> AepaScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn case_id(&self) -> Digest {
        self.case_id
    }

    #[must_use]
    pub const fn sequence(&self) -> &AepaPublicSequence {
        &self.sequence
    }

    #[must_use]
    pub fn to_spec(&self) -> AepaAdversarialCaseSpec {
        AepaAdversarialCaseSpec::new(
            self.profile,
            self.scenario,
            self.sequence.commands().to_vec(),
            self.sequence.limits(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaAdversarialMatrix {
    seed: AepaAdversarialMatrixSeed,
    source_digest: Digest,
    transition_digest: Digest,
    cases: Box<[AepaAdversarialCase]>,
    canonical_bytes: Box<[u8]>,
    matrix_digest: Digest,
}

impl AepaAdversarialMatrix {
    pub fn new(
        compiled: &AepaCompiledQsm,
        seed: AepaAdversarialMatrixSeed,
        specs: Vec<AepaAdversarialCaseSpec>,
        limits: AepaAdversarialMatrixLimits,
    ) -> Result<Self, AepaAdversarialMatrixError> {
        validate_matrix_limits(limits)?;
        if specs.len() != REQUIRED_CASES || specs.len() > limits.max_cases {
            return Err(AepaAdversarialMatrixError::CaseCoverage);
        }
        let mut cases = specs
            .into_iter()
            .map(|spec| build_case(compiled, seed, spec, limits))
            .collect::<Result<Vec<_>, _>>()?;
        cases.sort_by_key(|case| (case.profile, case.scenario));
        validate_case_coverage(&cases)?;
        let canonical_bytes = encode_matrix(compiled, seed, &cases)?;
        let matrix_digest = artifact_digest(MATRIX_DOMAIN, &canonical_bytes);
        Ok(Self {
            seed,
            source_digest: compiled.binding().source_digest,
            transition_digest: compiled.binding().transition_digest,
            cases: cases.into_boxed_slice(),
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            matrix_digest,
        })
    }

    #[must_use]
    pub const fn seed(&self) -> AepaAdversarialMatrixSeed {
        self.seed
    }

    #[must_use]
    pub fn cases(&self) -> &[AepaAdversarialCase] {
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
        compiled: &AepaCompiledQsm,
        limits: AepaAdversarialMatrixLimits,
    ) -> Result<(), AepaAdversarialMatrixError> {
        validate_matrix_limits(limits)?;
        if self.source_digest != compiled.binding().source_digest
            || self.transition_digest != compiled.binding().transition_digest
            || self.cases.len() != REQUIRED_CASES
            || self.cases.len() > limits.max_cases
        {
            return Err(AepaAdversarialMatrixError::MatrixBinding);
        }
        validate_case_coverage(&self.cases)?;
        for case in &self.cases {
            validate_scenario(
                case.scenario,
                case.sequence.commands(),
                case.sequence.limits(),
            )?;
            if case.sequence.commands().len() > limits.max_commands_per_case
                || case.case_id
                    != case_id(
                        compiled,
                        self.seed,
                        case.profile,
                        case.scenario,
                        &case.sequence,
                    )
            {
                return Err(AepaAdversarialMatrixError::MatrixBinding);
            }
        }
        let expected = encode_matrix(compiled, self.seed, &self.cases)?;
        if expected.as_slice() != self.canonical_bytes.as_ref()
            || artifact_digest(MATRIX_DOMAIN, &expected) != self.matrix_digest
        {
            return Err(AepaAdversarialMatrixError::MatrixBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaAdversarialCaseArtifact {
    pub case_id_sha256: String,
    pub profile_axis: String,
    pub scenario_axis: String,
    pub fault_class: String,
    pub outcome: AepaCaseOutcome,
    pub authorization_sha256: String,
    pub sequence_digest_sha256: String,
    pub verdict: AepaDifferentialVerdict,
    pub differential: AepaDifferentialArtifact,
}

impl AepaAdversarialCaseArtifact {
    fn validate(&self) -> Result<(), AepaAdversarialMatrixError> {
        if !is_sha256(&self.case_id_sha256)
            || !is_sha256(&self.authorization_sha256)
            || !is_sha256(&self.sequence_digest_sha256)
        {
            return Err(AepaAdversarialMatrixError::ArtifactContract);
        }
        let profile = profile_from_name(&self.profile_axis)
            .ok_or(AepaAdversarialMatrixError::ArtifactContract)?;
        let scenario = scenario_from_name(&self.scenario_axis)
            .ok_or(AepaAdversarialMatrixError::ArtifactContract)?;
        if self.fault_class != scenario.fault_class()
            || self.outcome != scenario.expected_outcome()
            || self.verdict != expected_verdict(self.outcome)
            || self.differential.verdict != self.verdict
            || self.differential.sequence_digest_sha256 != self.sequence_digest_sha256
        {
            return Err(AepaAdversarialMatrixError::FaultResourceConflation);
        }
        let _ = profile;
        self.differential
            .validate()
            .map_err(|error| AepaAdversarialMatrixError::Differential(error.to_string()))?;
        match self.outcome {
            AepaCaseOutcome::InjectedCounterexample => {
                if self.differential.evidence_origin
                    != AepaDifferentialEvidenceOrigin::InjectedTestFixture
                    || self.differential.injection_label.as_deref() != Some(TARGET_ONLY_LABEL)
                {
                    return Err(AepaAdversarialMatrixError::InjectionContract);
                }
            }
            AepaCaseOutcome::SemanticMatch | AepaCaseOutcome::ResourceUnresolved => {
                if self.differential.evidence_origin
                    != AepaDifferentialEvidenceOrigin::ExecutedSoftware
                    || self.differential.injection_label.is_some()
                {
                    return Err(AepaAdversarialMatrixError::InjectionContract);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaAdversarialExecutionArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub seed_sha256: String,
    pub matrix_digest_sha256: String,
    pub source_digest_sha256: String,
    pub transition_digest_sha256: String,
    pub hardware_status: String,
    pub verdict: AepaDifferentialVerdict,
    pub match_cases: u32,
    pub counterexample_cases: u32,
    pub unresolved_cases: u32,
    pub cases: Vec<AepaAdversarialCaseArtifact>,
}

impl AepaAdversarialExecutionArtifact {
    pub fn validate(&self) -> Result<(), AepaAdversarialMatrixError> {
        if self.schema_version != AEPA_ADVERSARIAL_MATRIX_VERSION
            || self.evaluator_version != AEPA_ADVERSARIAL_MATRIX_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.seed_sha256)
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.source_digest_sha256)
            || !is_sha256(&self.transition_digest_sha256)
            || self.cases.len() != REQUIRED_CASES
        {
            return Err(AepaAdversarialMatrixError::ArtifactContract);
        }
        let mut order = Vec::with_capacity(self.cases.len());
        let mut counts = [0_u32; 3];
        for case in &self.cases {
            case.validate()?;
            let profile = profile_from_name(&case.profile_axis)
                .ok_or(AepaAdversarialMatrixError::ArtifactContract)?;
            let scenario = scenario_from_name(&case.scenario_axis)
                .ok_or(AepaAdversarialMatrixError::ArtifactContract)?;
            order.push((profile, scenario));
            match case.verdict {
                AepaDifferentialVerdict::Match => counts[0] += 1,
                AepaDifferentialVerdict::Counterexample => counts[1] += 1,
                AepaDifferentialVerdict::Unresolved => counts[2] += 1,
            }
        }
        if !order.windows(2).all(|pair| pair[0] < pair[1])
            || self.match_cases != counts[0]
            || self.counterexample_cases != counts[1]
            || self.unresolved_cases != counts[2]
            || self.verdict != aggregate_counts(counts)
        {
            return Err(AepaAdversarialMatrixError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AepaAdversarialMatrixError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AepaAdversarialMatrixError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AepaAdversarialMatrixError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_aepa_adversarial_matrix(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    matrix: &AepaAdversarialMatrix,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaAdversarialExecutionArtifact, AepaAdversarialMatrixError> {
    matrix.validate_against(compiled, matrix_limits)?;
    let cases = matrix
        .cases()
        .iter()
        .map(|case| {
            evaluate_case(
                source,
                k7,
                compiled,
                p0_manifest,
                p1_manifest,
                p1_revalidation,
                public_step,
                case,
                engine_digests,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    build_execution_artifact(compiled, matrix, cases)
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_aepa_adversarial_case_spec(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    seed: AepaAdversarialMatrixSeed,
    spec: AepaAdversarialCaseSpec,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaAdversarialCaseArtifact, AepaAdversarialMatrixError> {
    validate_matrix_limits(matrix_limits)?;
    let case = build_case(compiled, seed, spec, matrix_limits)?;
    evaluate_case(
        source,
        k7,
        compiled,
        p0_manifest,
        p1_manifest,
        p1_revalidation,
        public_step,
        &case,
        engine_digests,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_aepa_adversarial_execution(
    artifact: &AepaAdversarialExecutionArtifact,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    matrix: &AepaAdversarialMatrix,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<(), AepaAdversarialMatrixError> {
    artifact.validate()?;
    let recomputed = evaluate_aepa_adversarial_matrix(
        source,
        k7,
        compiled,
        p0_manifest,
        p1_manifest,
        p1_revalidation,
        public_step,
        matrix,
        matrix_limits,
        engine_digests,
    )?;
    if &recomputed != artifact || recomputed.canonical_json()? != artifact.canonical_json()? {
        return Err(AepaAdversarialMatrixError::RecomputationMismatch);
    }
    Ok(())
}

fn build_case(
    compiled: &AepaCompiledQsm,
    seed: AepaAdversarialMatrixSeed,
    spec: AepaAdversarialCaseSpec,
    limits: AepaAdversarialMatrixLimits,
) -> Result<AepaAdversarialCase, AepaAdversarialMatrixError> {
    if spec.commands.len() > limits.max_commands_per_case {
        return Err(AepaAdversarialMatrixError::CommandLimit);
    }
    validate_scenario(spec.scenario, &spec.commands, spec.limits)?;
    let sequence = AepaPublicSequence::new(
        compiled,
        spec.commands,
        spec.limits,
        limits.max_commands_per_case,
    )
    .map_err(|error| AepaAdversarialMatrixError::Sequence(error.to_string()))?;
    let case_id = case_id(compiled, seed, spec.profile, spec.scenario, &sequence);
    Ok(AepaAdversarialCase {
        profile: spec.profile,
        scenario: spec.scenario,
        sequence,
        case_id,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_case(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    case: &AepaAdversarialCase,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaAdversarialCaseArtifact, AepaAdversarialMatrixError> {
    let profile = case.profile.deployment_profile();
    let (manifest, revalidation) = match profile {
        DeploymentProfile::P0PublicQuotientOnly => (p0_manifest, None),
        DeploymentProfile::P1SealedAdmission => (p1_manifest, Some(p1_revalidation)),
    };
    let authorization = authorize_aepa_profile(
        profile,
        manifest,
        source,
        k7,
        compiled,
        revalidation,
        public_step,
    )
    .map_err(|error| AepaAdversarialMatrixError::ProfileAuthorization(error.to_string()))?;
    let base = evaluate_aepa_differential(compiled, case.sequence(), engine_digests)
        .map_err(|error| AepaAdversarialMatrixError::Differential(error.to_string()))?;
    let differential = if case.scenario == AepaScenarioAxis::TargetOnlyAdmission {
        inject_target_only_admission(compiled, &base)?
    } else {
        base
    };
    let outcome = case.scenario.expected_outcome();
    let artifact = AepaAdversarialCaseArtifact {
        case_id_sha256: hex(case.case_id.as_bytes()),
        profile_axis: case.profile.name().to_owned(),
        scenario_axis: case.scenario.name().to_owned(),
        fault_class: case.scenario.fault_class().to_owned(),
        outcome,
        authorization_sha256: hex(authorization.authorization_digest().as_bytes()),
        sequence_digest_sha256: hex(case.sequence.digest().as_bytes()),
        verdict: differential.verdict,
        differential,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn inject_target_only_admission(
    compiled: &AepaCompiledQsm,
    base: &AepaDifferentialArtifact,
) -> Result<AepaDifferentialArtifact, AepaAdversarialMatrixError> {
    if base.verdict != AepaDifferentialVerdict::Match {
        return Err(AepaAdversarialMatrixError::InjectionContract);
    }
    let mut engines = base.oracle.engines.clone();
    let wasmtime = engines
        .iter_mut()
        .find(|run| run.input.engine.name == "wasmtime")
        .ok_or(AepaAdversarialMatrixError::MissingWasmtime)?;
    let insertion = wasmtime
        .trace
        .iter()
        .position(|event| matches!(event, ObservableEvent::EmitFrame { .. }))
        .ok_or(AepaAdversarialMatrixError::MissingFrame)?
        + 1;
    wasmtime.trace.insert(
        insertion,
        ObservableEvent::EmitAction {
            action: compiled.admission_action(),
            slot: 0,
            return_code: 0,
        },
    );
    let oracle = DifferentialOracle::evaluate(base.oracle.reference.clone(), engines)
        .map_err(|error| AepaAdversarialMatrixError::Differential(error.to_string()))?;
    if oracle.verdict != DifferentialVerdict::Counterexample {
        return Err(AepaAdversarialMatrixError::InjectionContract);
    }
    build_aepa_injected_fixture_artifact(base, oracle, TARGET_ONLY_LABEL)
        .map_err(|error| AepaAdversarialMatrixError::Differential(error.to_string()))
}

fn build_execution_artifact(
    compiled: &AepaCompiledQsm,
    matrix: &AepaAdversarialMatrix,
    cases: Vec<AepaAdversarialCaseArtifact>,
) -> Result<AepaAdversarialExecutionArtifact, AepaAdversarialMatrixError> {
    let mut counts = [0_u32; 3];
    for case in &cases {
        match case.verdict {
            AepaDifferentialVerdict::Match => counts[0] += 1,
            AepaDifferentialVerdict::Counterexample => counts[1] += 1,
            AepaDifferentialVerdict::Unresolved => counts[2] += 1,
        }
    }
    let artifact = AepaAdversarialExecutionArtifact {
        schema_version: AEPA_ADVERSARIAL_MATRIX_VERSION.to_owned(),
        evaluator_version: AEPA_ADVERSARIAL_MATRIX_VERSION.to_owned(),
        seed_sha256: sha256_hex(&matrix.seed.as_bytes()),
        matrix_digest_sha256: hex(matrix.matrix_digest.as_bytes()),
        source_digest_sha256: hex(compiled.binding().source_digest.as_bytes()),
        transition_digest_sha256: hex(compiled.binding().transition_digest.as_bytes()),
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

fn validate_matrix_limits(
    limits: AepaAdversarialMatrixLimits,
) -> Result<(), AepaAdversarialMatrixError> {
    if limits.max_cases < REQUIRED_CASES || limits.max_commands_per_case == 0 {
        return Err(AepaAdversarialMatrixError::InvalidLimits);
    }
    Ok(())
}

fn validate_case_coverage(cases: &[AepaAdversarialCase]) -> Result<(), AepaAdversarialMatrixError> {
    let expected = AepaProfileAxis::ALL
        .iter()
        .flat_map(|profile| {
            AepaScenarioAxis::ALL
                .iter()
                .map(move |scenario| (*profile, *scenario))
        })
        .collect::<BTreeSet<_>>();
    let actual = cases
        .iter()
        .map(|case| (case.profile, case.scenario))
        .collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != cases.len() {
        return Err(AepaAdversarialMatrixError::CaseCoverage);
    }
    Ok(())
}

fn validate_scenario(
    scenario: AepaScenarioAxis,
    commands: &[ContextCommand],
    limits: ExecutionLimits,
) -> Result<(), AepaAdversarialMatrixError> {
    if commands.len() < 2
        || commands.last().map(|command| command.family) != Some(ContextFamily::Stop)
        || commands[..commands.len() - 1]
            .iter()
            .any(|command| command.family == ContextFamily::Stop)
        || limits.fuel == 0
        || limits.max_memory_pages == 0
        || limits.max_host_calls == 0
        || limits.timeout_ms == 0
    {
        return Err(AepaAdversarialMatrixError::ScenarioContract);
    }
    let contains = |family: ContextFamily, input: AepaPublicInput| {
        commands.iter().any(|command| {
            command.family == family
                && command.kind == family.command_kind()
                && command.fault == input as u8
        })
    };
    let valid = match scenario {
        AepaScenarioAxis::Normal | AepaScenarioAxis::TargetOnlyAdmission => {
            contains(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission)
        }
        AepaScenarioAxis::Replay => {
            contains(ContextFamily::CrossServiceReplay, AepaPublicInput::Replay)
        }
        AepaScenarioAxis::Expiry => contains(ContextFamily::Deadline, AepaPublicInput::Expired),
        AepaScenarioAxis::Downgrade => {
            contains(ContextFamily::ServiceCollusion, AepaPublicInput::Downgrade)
        }
        AepaScenarioAxis::WrongBinding => contains(
            ContextFamily::ServiceCollusion,
            AepaPublicInput::WrongBinding,
        ),
        AepaScenarioAxis::Duplicate => commands[..commands.len() - 1]
            .windows(2)
            .any(|pair| pair[0] == pair[1]),
        AepaScenarioAxis::FuelBoundary => {
            limits.fuel == 1 && contains(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission)
        }
        AepaScenarioAxis::HostCallBoundary => {
            limits.max_host_calls == 1
                && contains(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission)
        }
    };
    if !valid {
        return Err(AepaAdversarialMatrixError::ScenarioContract);
    }
    if matches!(
        scenario,
        AepaScenarioAxis::Normal
            | AepaScenarioAxis::Replay
            | AepaScenarioAxis::Expiry
            | AepaScenarioAxis::Downgrade
            | AepaScenarioAxis::WrongBinding
            | AepaScenarioAxis::Duplicate
            | AepaScenarioAxis::TargetOnlyAdmission
    ) && (limits.fuel == 1 || limits.max_host_calls == 1)
    {
        return Err(AepaAdversarialMatrixError::FaultResourceConflation);
    }
    Ok(())
}

fn case_id(
    compiled: &AepaCompiledQsm,
    seed: AepaAdversarialMatrixSeed,
    profile: AepaProfileAxis,
    scenario: AepaScenarioAxis,
    sequence: &AepaPublicSequence,
) -> Digest {
    let mut bytes = Vec::with_capacity(130);
    bytes.extend_from_slice(&seed.as_bytes());
    bytes.extend_from_slice(compiled.binding().source_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().transition_digest.as_bytes());
    bytes.push(profile as u8);
    bytes.push(scenario as u8);
    bytes.extend_from_slice(sequence.digest().as_bytes());
    artifact_digest(CASE_DOMAIN, &bytes)
}

fn encode_matrix(
    compiled: &AepaCompiledQsm,
    seed: AepaAdversarialMatrixSeed,
    cases: &[AepaAdversarialCase],
) -> Result<Vec<u8>, AepaAdversarialMatrixError> {
    let count = u16::try_from(cases.len()).map_err(|_| AepaAdversarialMatrixError::Arithmetic)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MATRIX_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&seed.as_bytes());
    bytes.extend_from_slice(compiled.binding().source_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().transition_digest.as_bytes());
    for case in cases {
        bytes.push(case.profile as u8);
        bytes.push(case.scenario as u8);
        bytes.extend_from_slice(case.case_id.as_bytes());
        bytes.extend_from_slice(case.sequence.digest().as_bytes());
        let limits = case.sequence.limits();
        bytes.extend_from_slice(&limits.fuel.to_le_bytes());
        bytes.extend_from_slice(&limits.max_memory_pages.to_le_bytes());
        bytes.extend_from_slice(&limits.max_host_calls.to_le_bytes());
        bytes.extend_from_slice(&limits.timeout_ms.to_le_bytes());
        let command_count = u16::try_from(case.sequence.commands().len())
            .map_err(|_| AepaAdversarialMatrixError::Arithmetic)?;
        bytes.extend_from_slice(&command_count.to_le_bytes());
        for command in case.sequence.commands() {
            bytes.push(command.family as u8);
            bytes.push(command.kind as u8);
            bytes.extend_from_slice(&command.service_alias.to_le_bytes());
            bytes.extend_from_slice(&command.public_slot.to_le_bytes());
            bytes.push(command.fault);
            bytes.extend_from_slice(&command.payload_tag.to_le_bytes());
        }
    }
    Ok(bytes)
}

const fn expected_verdict(outcome: AepaCaseOutcome) -> AepaDifferentialVerdict {
    match outcome {
        AepaCaseOutcome::SemanticMatch => AepaDifferentialVerdict::Match,
        AepaCaseOutcome::InjectedCounterexample => AepaDifferentialVerdict::Counterexample,
        AepaCaseOutcome::ResourceUnresolved => AepaDifferentialVerdict::Unresolved,
    }
}

const fn aggregate_counts(counts: [u32; 3]) -> AepaDifferentialVerdict {
    if counts[1] > 0 {
        AepaDifferentialVerdict::Counterexample
    } else if counts[2] > 0 {
        AepaDifferentialVerdict::Unresolved
    } else {
        AepaDifferentialVerdict::Match
    }
}

fn profile_from_name(name: &str) -> Option<AepaProfileAxis> {
    AepaProfileAxis::ALL
        .iter()
        .copied()
        .find(|profile| profile.name() == name)
}

fn scenario_from_name(name: &str) -> Option<AepaScenarioAxis> {
    AepaScenarioAxis::ALL
        .iter()
        .copied()
        .find(|scenario| scenario.name() == name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AepaAdversarialMatrixError {
    #[error("AEPA adversarial matrix seed must be nonzero")]
    ZeroSeed,
    #[error("AEPA adversarial matrix limits are invalid")]
    InvalidLimits,
    #[error("AEPA adversarial matrix must contain the exact P0/P1 scenario product")]
    CaseCoverage,
    #[error("AEPA adversarial command count exceeds the configured bound")]
    CommandLimit,
    #[error("AEPA adversarial scenario violates its typed public command contract")]
    ScenarioContract,
    #[error("AEPA fault and resource exhaustion classifications must remain distinct")]
    FaultResourceConflation,
    #[error("AEPA public sequence failed validation: {0}")]
    Sequence(String),
    #[error("AEPA adversarial matrix does not match the compiled QSM")]
    MatrixBinding,
    #[error("AEPA profile authorization failed closed: {0}")]
    ProfileAuthorization(String),
    #[error("AEPA differential evaluation failed: {0}")]
    Differential(String),
    #[error("AEPA target-only injection requires the Wasmtime participant")]
    MissingWasmtime,
    #[error("AEPA target-only injection requires a public frame")]
    MissingFrame,
    #[error("AEPA target-only admission injection violated its fixture contract")]
    InjectionContract,
    #[error("AEPA adversarial artifact violated its canonical contract")]
    ArtifactContract,
    #[error("AEPA adversarial artifact serialization failed: {0}")]
    Serialization(String),
    #[error("AEPA adversarial execution did not recompute byte-identically")]
    RecomputationMismatch,
    #[error("AEPA adversarial canonical encoding overflow")]
    Arithmetic,
}
