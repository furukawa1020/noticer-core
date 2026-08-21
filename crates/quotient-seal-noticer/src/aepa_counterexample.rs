use std::fmt::Display;

use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, DifferentialCounterexampleKind, DifferentialVerdict, ExecutionLimits,
    ObservableAxis,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_aepa_adversarial_case_spec, AepaAdversarialCase, AepaAdversarialCaseArtifact,
    AepaAdversarialCaseSpec, AepaAdversarialExecutionArtifact, AepaAdversarialMatrix,
    AepaAdversarialMatrixLimits, AepaAdversarialMatrixSeed, AepaCompiledQsm,
    AepaDifferentialArtifact, AepaDifferentialVerdict, AepaEngineDigests, AepaK7Binding,
    AepaP1Revalidation, AepaProfileAxis, AepaPublicSourceArtifact, AepaScenarioAxis,
    NoticerQsmManifest,
};

pub const AEPA_COUNTEREXAMPLE_BUNDLE_VERSION: &str = "noticer-aepa-counterexample-bundle/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const SHRINK_ORDER: [&str; 2] = [
    "REMOVE_NON_STOP_COMMANDS_REVERSE_INDEX_KEEP_ONE",
    "ZERO_PAYLOAD_TAG_ASCENDING_INDEX",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaCounterexampleInput {
    seed: AepaAdversarialMatrixSeed,
    profile: AepaProfileAxis,
    scenario: AepaScenarioAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AepaCounterexampleInput {
    pub fn new(
        seed: AepaAdversarialMatrixSeed,
        profile: AepaProfileAxis,
        scenario: AepaScenarioAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Result<Self, AepaCounterexampleError> {
        validate_commands(&commands, limits)?;
        Ok(Self {
            seed,
            profile,
            scenario,
            commands,
            limits,
        })
    }

    pub fn from_case(
        seed: AepaAdversarialMatrixSeed,
        case: &AepaAdversarialCase,
    ) -> Result<Self, AepaCounterexampleError> {
        Self::new(
            seed,
            case.profile(),
            case.scenario(),
            case.sequence().commands().to_vec(),
            case.sequence().limits(),
        )
    }

    #[must_use]
    pub const fn seed(&self) -> AepaAdversarialMatrixSeed {
        self.seed
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

    #[must_use]
    pub fn to_case_spec(&self) -> AepaAdversarialCaseSpec {
        AepaAdversarialCaseSpec::new(
            self.profile,
            self.scenario,
            self.commands.clone(),
            self.limits,
        )
    }

    pub fn artifact(&self) -> Result<AepaCounterexampleInputArtifact, AepaCounterexampleError> {
        let commands = self
            .commands
            .iter()
            .map(AepaCommandArtifact::from)
            .collect::<Vec<_>>();
        let limits = AepaLimitsArtifact::from(self.limits);
        let input_sha256 =
            input_sha256(self.seed, self.profile, self.scenario, &commands, &limits)?;
        let artifact = AepaCounterexampleInputArtifact {
            seed_sha256: sha256_hex(&self.seed.as_bytes()),
            profile_axis: self.profile.name().to_owned(),
            scenario_axis: self.scenario.name().to_owned(),
            commands,
            limits,
            input_sha256,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaCommandArtifact {
    pub family_code: u8,
    pub kind_code: u8,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

impl From<&ContextCommand> for AepaCommandArtifact {
    fn from(command: &ContextCommand) -> Self {
        Self {
            family_code: command.family as u8,
            kind_code: command.kind as u8,
            service_alias: command.service_alias,
            public_slot: command.public_slot,
            fault: command.fault,
            payload_tag: command.payload_tag,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaLimitsArtifact {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

impl From<ExecutionLimits> for AepaLimitsArtifact {
    fn from(limits: ExecutionLimits) -> Self {
        Self {
            fuel: limits.fuel,
            max_memory_pages: limits.max_memory_pages,
            max_host_calls: limits.max_host_calls,
            timeout_ms: limits.timeout_ms,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaCounterexampleInputArtifact {
    pub seed_sha256: String,
    pub profile_axis: String,
    pub scenario_axis: String,
    pub commands: Vec<AepaCommandArtifact>,
    pub limits: AepaLimitsArtifact,
    pub input_sha256: String,
}

impl AepaCounterexampleInputArtifact {
    fn validate(&self) -> Result<(), AepaCounterexampleError> {
        if !is_sha256(&self.seed_sha256)
            || !is_sha256(&self.input_sha256)
            || !AepaProfileAxis::ALL
                .iter()
                .any(|profile| profile.name() == self.profile_axis)
            || !AepaScenarioAxis::ALL
                .iter()
                .any(|scenario| scenario.name() == self.scenario_axis)
            || self.commands.len() < 2
            || self.commands.last().map(|command| command.family_code)
                != Some(ContextFamily::Stop as u8)
            || self.commands[..self.commands.len() - 1]
                .iter()
                .any(|command| command.family_code == ContextFamily::Stop as u8)
            || self.limits.fuel == 0
            || self.limits.max_memory_pages == 0
            || self.limits.max_host_calls == 0
            || self.limits.timeout_ms == 0
        {
            return Err(AepaCounterexampleError::InputContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaComparisonSignature {
    Trace {
        left_axis: Option<ObservableAxis>,
        right_axis: Option<ObservableAxis>,
    },
    Termination {
        left_axis: ObservableAxis,
        right_axis: ObservableAxis,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaDifferenceOrigin {
    SourceRefinement,
    DifferentialOracle {
        counterexample_kind: DifferentialCounterexampleKind,
        left_participant: String,
        right_participant: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaDifferenceSignature {
    pub origin: AepaDifferenceOrigin,
    pub comparison: AepaComparisonSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaShrinkOperation {
    RemoveCommand { index: u32 },
    ZeroPayloadTag { index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaShrinkOutcome {
    Preserved,
    NotCounterexample,
    DifferentTypedDifference,
    EvaluationError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaShrinkAttempt {
    pub ordinal: u32,
    pub operation: AepaShrinkOperation,
    pub before_input_sha256: String,
    pub candidate_input_sha256: String,
    pub outcome: AepaShrinkOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaCounterexampleCaseArtifact {
    pub input: AepaCounterexampleInputArtifact,
    pub result_sha256: String,
    pub result: AepaAdversarialCaseArtifact,
}

impl AepaCounterexampleCaseArtifact {
    fn new(
        input: &AepaCounterexampleInput,
        result: AepaAdversarialCaseArtifact,
    ) -> Result<Self, AepaCounterexampleError> {
        validate_case_result(&result)?;
        Ok(Self {
            input: input.artifact()?,
            result_sha256: case_result_sha256(&result)?,
            result,
        })
    }

    fn validate(&self) -> Result<(), AepaCounterexampleError> {
        self.input.validate()?;
        validate_case_result(&self.result)?;
        if self.result_sha256 != case_result_sha256(&self.result)?
            || self.input.profile_axis != self.result.profile_axis
            || self.input.scenario_axis != self.result.scenario_axis
        {
            return Err(AepaCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaCounterexampleBundle {
    pub schema_version: String,
    pub shrinker_version: String,
    pub matrix_digest_sha256: String,
    pub original_case_id_sha256: String,
    pub hardware_status: String,
    pub shrink_order: Vec<String>,
    pub difference_signature: AepaDifferenceSignature,
    pub original_first_difference: ComparisonPoint,
    pub minimized_first_difference: ComparisonPoint,
    pub original: AepaCounterexampleCaseArtifact,
    pub minimized: AepaCounterexampleCaseArtifact,
    pub attempts: Vec<AepaShrinkAttempt>,
}

impl AepaCounterexampleBundle {
    pub fn validate(&self) -> Result<(), AepaCounterexampleError> {
        if self.schema_version != AEPA_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.shrinker_version != AEPA_COUNTEREXAMPLE_BUNDLE_VERSION
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.original_case_id_sha256)
            || self.hardware_status != HARDWARE_STATUS
            || self.shrink_order != shrink_order()
        {
            return Err(AepaCounterexampleError::ArtifactContract);
        }
        self.original.validate()?;
        self.minimized.validate()?;
        if self.original.result.case_id_sha256 != self.original_case_id_sha256
            || self.original.result.verdict != AepaDifferentialVerdict::Counterexample
            || self.minimized.result.verdict != AepaDifferentialVerdict::Counterexample
        {
            return Err(AepaCounterexampleError::OriginalNotCounterexample);
        }
        let (original_signature, original_point) =
            first_typed_difference(&self.original.result.differential)?;
        let (minimized_signature, minimized_point) =
            first_typed_difference(&self.minimized.result.differential)?;
        if original_signature != self.difference_signature
            || minimized_signature != self.difference_signature
            || original_point != self.original_first_difference
            || minimized_point != self.minimized_first_difference
            || self.attempts.iter().enumerate().any(|(index, attempt)| {
                usize::try_from(attempt.ordinal) != Ok(index)
                    || !is_sha256(&attempt.before_input_sha256)
                    || !is_sha256(&attempt.candidate_input_sha256)
            })
        {
            return Err(AepaCounterexampleError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AepaCounterexampleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AepaCounterexampleError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AepaCounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn shrink_aepa_counterexample<F, E>(
    matrix_digest_sha256: String,
    original_case_id_sha256: String,
    original_input: AepaCounterexampleInput,
    observed: AepaAdversarialCaseArtifact,
    mut evaluator: F,
) -> Result<AepaCounterexampleBundle, AepaCounterexampleError>
where
    F: FnMut(&AepaCounterexampleInput) -> Result<AepaAdversarialCaseArtifact, E>,
    E: Display,
{
    if !is_sha256(&matrix_digest_sha256) || !is_sha256(&original_case_id_sha256) {
        return Err(AepaCounterexampleError::InvalidSha256);
    }
    validate_case_result(&observed)?;
    if observed.verdict != AepaDifferentialVerdict::Counterexample
        || observed.case_id_sha256 != original_case_id_sha256
    {
        return Err(AepaCounterexampleError::OriginalNotCounterexample);
    }
    let reproduced = evaluator(&original_input)
        .map_err(|error| AepaCounterexampleError::Evaluation(error.to_string()))?;
    validate_case_result(&reproduced)?;
    if reproduced != observed {
        return Err(AepaCounterexampleError::OriginalReproductionMismatch);
    }
    let (difference_signature, original_first_difference) =
        first_typed_difference(&observed.differential)?;
    let mut state = ShrinkState {
        input: original_input.clone(),
        result: observed.clone(),
        first_difference: original_first_difference.clone(),
    };
    let mut attempts = Vec::new();

    for index in (0..state.input.commands.len().saturating_sub(1)).rev() {
        if state.input.commands.len() <= 2 {
            break;
        }
        let mut candidate = state.input.clone();
        candidate.commands.remove(index);
        attempt_candidate(
            &mut state,
            &difference_signature,
            candidate,
            AepaShrinkOperation::RemoveCommand {
                index: index_u32(index)?,
            },
            &mut attempts,
            &mut evaluator,
        )?;
    }
    for index in 0..state.input.commands.len().saturating_sub(1) {
        if state.input.commands[index].payload_tag == 0 {
            continue;
        }
        let mut candidate = state.input.clone();
        candidate.commands[index].payload_tag = 0;
        attempt_candidate(
            &mut state,
            &difference_signature,
            candidate,
            AepaShrinkOperation::ZeroPayloadTag {
                index: index_u32(index)?,
            },
            &mut attempts,
            &mut evaluator,
        )?;
    }

    let bundle = AepaCounterexampleBundle {
        schema_version: AEPA_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        shrinker_version: AEPA_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        matrix_digest_sha256,
        original_case_id_sha256,
        hardware_status: HARDWARE_STATUS.to_owned(),
        shrink_order: shrink_order(),
        difference_signature,
        original_first_difference,
        minimized_first_difference: state.first_difference,
        original: AepaCounterexampleCaseArtifact::new(&original_input, observed)?,
        minimized: AepaCounterexampleCaseArtifact::new(&state.input, state.result)?,
        attempts,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn verify_aepa_counterexample_bundle_with<F, E>(
    bundle: &AepaCounterexampleBundle,
    matrix_digest_sha256: String,
    original_case_id_sha256: String,
    original_input: AepaCounterexampleInput,
    observed: AepaAdversarialCaseArtifact,
    evaluator: F,
) -> Result<(), AepaCounterexampleError>
where
    F: FnMut(&AepaCounterexampleInput) -> Result<AepaAdversarialCaseArtifact, E>,
    E: Display,
{
    bundle.validate()?;
    let recomputed = shrink_aepa_counterexample(
        matrix_digest_sha256,
        original_case_id_sha256,
        original_input,
        observed,
        evaluator,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AepaCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_aepa_counterexample_bundle(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    matrix: &AepaAdversarialMatrix,
    execution: &AepaAdversarialExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaCounterexampleBundle, AepaCounterexampleError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| AepaCounterexampleError::Matrix(error.to_string()))?;
    validate_execution_binding(matrix, execution)?;
    let original_case = matrix
        .cases()
        .iter()
        .find(|case| hex(case.case_id().as_bytes()) == original_case_id_sha256)
        .ok_or(AepaCounterexampleError::CaseNotFound)?;
    let observed = execution
        .cases
        .iter()
        .find(|case| case.case_id_sha256 == original_case_id_sha256)
        .cloned()
        .ok_or(AepaCounterexampleError::CaseResultNotFound)?;
    let input = AepaCounterexampleInput::from_case(matrix.seed(), original_case)?;
    let matrix_digest = hex(matrix.matrix_digest().as_bytes());
    shrink_aepa_counterexample(
        matrix_digest,
        original_case_id_sha256.to_owned(),
        input,
        observed,
        |candidate| {
            evaluate_candidate(
                source,
                k7,
                compiled,
                p0_manifest,
                p1_manifest,
                p1_revalidation,
                public_step,
                candidate,
                matrix_limits,
                engine_digests,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_aepa_counterexample_bundle(
    bundle: &AepaCounterexampleBundle,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    matrix: &AepaAdversarialMatrix,
    execution: &AepaAdversarialExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<(), AepaCounterexampleError> {
    bundle.validate()?;
    let recomputed = build_aepa_counterexample_bundle(
        source,
        k7,
        compiled,
        p0_manifest,
        p1_manifest,
        p1_revalidation,
        public_step,
        matrix,
        execution,
        original_case_id_sha256,
        matrix_limits,
        engine_digests,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AepaCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

struct ShrinkState {
    input: AepaCounterexampleInput,
    result: AepaAdversarialCaseArtifact,
    first_difference: ComparisonPoint,
}

fn attempt_candidate<F, E>(
    state: &mut ShrinkState,
    expected_signature: &AepaDifferenceSignature,
    candidate: AepaCounterexampleInput,
    operation: AepaShrinkOperation,
    attempts: &mut Vec<AepaShrinkAttempt>,
    evaluator: &mut F,
) -> Result<(), AepaCounterexampleError>
where
    F: FnMut(&AepaCounterexampleInput) -> Result<AepaAdversarialCaseArtifact, E>,
    E: Display,
{
    let before_input_sha256 = state.input.artifact()?.input_sha256;
    let candidate_input_sha256 = candidate.artifact()?.input_sha256;
    let evaluation = evaluator(&candidate);
    let (outcome, accepted) = match evaluation {
        Err(_) => (AepaShrinkOutcome::EvaluationError, None),
        Ok(result) if validate_case_result(&result).is_err() => {
            (AepaShrinkOutcome::EvaluationError, None)
        }
        Ok(result) if result.verdict != AepaDifferentialVerdict::Counterexample => {
            (AepaShrinkOutcome::NotCounterexample, None)
        }
        Ok(result) => match first_typed_difference(&result.differential) {
            Ok((signature, first_difference)) if &signature == expected_signature => (
                AepaShrinkOutcome::Preserved,
                Some((result, first_difference)),
            ),
            Ok(_) => (AepaShrinkOutcome::DifferentTypedDifference, None),
            Err(_) => (AepaShrinkOutcome::EvaluationError, None),
        },
    };
    attempts.push(AepaShrinkAttempt {
        ordinal: index_u32(attempts.len())?,
        operation,
        before_input_sha256,
        candidate_input_sha256,
        outcome,
    });
    if let Some((result, first_difference)) = accepted {
        state.input = candidate;
        state.result = result;
        state.first_difference = first_difference;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_candidate(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    p0_manifest: &NoticerQsmManifest,
    p1_manifest: &NoticerQsmManifest,
    p1_revalidation: &AepaP1Revalidation,
    public_step: u32,
    input: &AepaCounterexampleInput,
    matrix_limits: AepaAdversarialMatrixLimits,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaAdversarialCaseArtifact, String> {
    evaluate_aepa_adversarial_case_spec(
        source,
        k7,
        compiled,
        p0_manifest,
        p1_manifest,
        p1_revalidation,
        public_step,
        input.seed,
        input.to_case_spec(),
        matrix_limits,
        engine_digests,
    )
    .map_err(|error| error.to_string())
}

fn first_typed_difference(
    artifact: &AepaDifferentialArtifact,
) -> Result<(AepaDifferenceSignature, ComparisonPoint), AepaCounterexampleError> {
    artifact
        .validate()
        .map_err(|error| AepaCounterexampleError::Differential(error.to_string()))?;
    if artifact.source_refinement.verdict == AepaDifferentialVerdict::Counterexample {
        let point = artifact
            .source_refinement
            .first_difference
            .clone()
            .ok_or(AepaCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AepaDifferenceSignature {
                origin: AepaDifferenceOrigin::SourceRefinement,
                comparison: comparison_signature(&point),
            },
            point,
        ));
    }
    if artifact.oracle.verdict == DifferentialVerdict::Counterexample {
        let counterexample = artifact
            .oracle
            .counterexamples
            .first()
            .ok_or(AepaCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AepaDifferenceSignature {
                origin: AepaDifferenceOrigin::DifferentialOracle {
                    counterexample_kind: counterexample.kind,
                    left_participant: counterexample.left_participant.clone(),
                    right_participant: counterexample.right_participant.clone(),
                },
                comparison: comparison_signature(&counterexample.first_difference),
            },
            counterexample.first_difference.clone(),
        ));
    }
    Err(AepaCounterexampleError::MissingFirstDifference)
}

fn comparison_signature(point: &ComparisonPoint) -> AepaComparisonSignature {
    match point {
        ComparisonPoint::Trace {
            left_axis,
            right_axis,
            ..
        } => AepaComparisonSignature::Trace {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
        ComparisonPoint::Termination {
            left_axis,
            right_axis,
            ..
        } => AepaComparisonSignature::Termination {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
    }
}

fn validate_execution_binding(
    matrix: &AepaAdversarialMatrix,
    execution: &AepaAdversarialExecutionArtifact,
) -> Result<(), AepaCounterexampleError> {
    execution
        .validate()
        .map_err(|error| AepaCounterexampleError::MatrixExecution(error.to_string()))?;
    if execution.matrix_digest_sha256 != hex(matrix.matrix_digest().as_bytes())
        || execution.cases.len() != matrix.cases().len()
        || execution
            .cases
            .iter()
            .zip(matrix.cases())
            .any(|(result, case)| result.case_id_sha256 != hex(case.case_id().as_bytes()))
    {
        return Err(AepaCounterexampleError::MatrixBinding);
    }
    Ok(())
}

fn validate_case_result(
    result: &AepaAdversarialCaseArtifact,
) -> Result<(), AepaCounterexampleError> {
    result
        .validate()
        .map_err(|error| AepaCounterexampleError::Differential(error.to_string()))?;
    if result.verdict != AepaDifferentialVerdict::Counterexample {
        return Err(AepaCounterexampleError::OriginalNotCounterexample);
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
) -> Result<(), AepaCounterexampleError> {
    if commands.len() < 2
        || commands.last().map(|command| command.family) != Some(ContextFamily::Stop)
        || commands[..commands.len() - 1]
            .iter()
            .any(|command| command.family == ContextFamily::Stop)
        || commands
            .iter()
            .any(|command| command.kind != command.family.command_kind())
        || limits.fuel == 0
        || limits.max_memory_pages == 0
        || limits.max_host_calls == 0
        || limits.timeout_ms == 0
    {
        return Err(AepaCounterexampleError::InputContract);
    }
    Ok(())
}

fn input_sha256(
    seed: AepaAdversarialMatrixSeed,
    profile: AepaProfileAxis,
    scenario: AepaScenarioAxis,
    commands: &[AepaCommandArtifact],
    limits: &AepaLimitsArtifact,
) -> Result<String, AepaCounterexampleError> {
    #[derive(Serialize)]
    struct Input<'a> {
        seed: [u8; 32],
        profile_axis: &'a str,
        scenario_axis: &'a str,
        commands: &'a [AepaCommandArtifact],
        limits: &'a AepaLimitsArtifact,
    }
    let bytes = serde_json::to_vec(&Input {
        seed: seed.as_bytes(),
        profile_axis: profile.name(),
        scenario_axis: scenario.name(),
        commands,
        limits,
    })
    .map_err(|error| AepaCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn case_result_sha256(
    result: &AepaAdversarialCaseArtifact,
) -> Result<String, AepaCounterexampleError> {
    result
        .validate()
        .map_err(|error| AepaCounterexampleError::Differential(error.to_string()))?;
    let bytes = serde_json::to_vec(result)
        .map_err(|error| AepaCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn shrink_order() -> Vec<String> {
    SHRINK_ORDER
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn index_u32(index: usize) -> Result<u32, AepaCounterexampleError> {
    u32::try_from(index).map_err(|_| AepaCounterexampleError::Arithmetic)
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
pub enum AepaCounterexampleError {
    #[error("counterexample input violates the frozen public command contract")]
    InputContract,
    #[error("expected a lowercase SHA-256 value")]
    InvalidSha256,
    #[error("counterexample bundle violates its canonical artifact contract")]
    ArtifactContract,
    #[error("the selected original case is not a counterexample")]
    OriginalNotCounterexample,
    #[error("the original counterexample did not reproduce byte-identically")]
    OriginalReproductionMismatch,
    #[error("counterexample artifact has no typed first difference")]
    MissingFirstDifference,
    #[error("counterexample bundle recomputation differs from the stored bundle")]
    RecomputationMismatch,
    #[error("matrix execution and matrix bytes are not bound")]
    MatrixBinding,
    #[error("selected matrix case was not found")]
    CaseNotFound,
    #[error("selected matrix case result was not found")]
    CaseResultNotFound,
    #[error("candidate evaluation failed: {0}")]
    Evaluation(String),
    #[error("matrix validation failed: {0}")]
    Matrix(String),
    #[error("matrix execution validation failed: {0}")]
    MatrixExecution(String),
    #[error("differential artifact validation failed: {0}")]
    Differential(String),
    #[error("counterexample artifact serialization failed: {0}")]
    Serialization(String),
    #[error("counterexample canonical encoding overflow")]
    Arithmetic,
}
