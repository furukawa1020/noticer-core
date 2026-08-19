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
    evaluate_aets_adversarial_matrix, AetsAdversarialCase, AetsAdversarialCaseSpec,
    AetsAdversarialMatrix, AetsCompiledQsm, AetsDifferentialArtifact, AetsDifferentialVerdict,
    AetsEngineDigests, AetsHostAxis, AetsHostInjection, AetsMatrixCaseArtifact,
    AetsMatrixExecutionArtifact, AetsMatrixLimits, AetsResourceAxis, AetsScenarioAxis,
};

pub const AETS_COUNTEREXAMPLE_BUNDLE_VERSION: &str = "noticer-aets-counterexample-bundle/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const SHRINK_ORDER: [&str; 5] = [
    "REMOVE_NON_STOP_COMMANDS_REVERSE_INDEX_KEEP_ONE",
    "ZERO_PAYLOAD_TAG_ASCENDING_INDEX",
    "ZERO_FAULT_ASCENDING_INDEX",
    "ZERO_SERVICE_ALIAS_ASCENDING_INDEX",
    "ZERO_PUBLIC_SLOT_ASCENDING_INDEX",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsCounterexampleInput {
    scenario: AetsScenarioAxis,
    host: AetsHostAxis,
    resource: AetsResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AetsCounterexampleInput {
    pub fn new(
        scenario: AetsScenarioAxis,
        host: AetsHostAxis,
        resource: AetsResourceAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Result<Self, AetsCounterexampleError> {
        validate_commands(&commands, limits)?;
        Ok(Self {
            scenario,
            host,
            resource,
            commands,
            limits,
        })
    }

    pub fn from_case(case: &AetsAdversarialCase) -> Result<Self, AetsCounterexampleError> {
        Self::new(
            case.scenario(),
            case.host(),
            case.resource(),
            case.commands().to_vec(),
            case.limits(),
        )
    }

    #[must_use]
    pub const fn scenario(&self) -> AetsScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn host(&self) -> AetsHostAxis {
        self.host
    }

    #[must_use]
    pub const fn resource(&self) -> AetsResourceAxis {
        self.resource
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
    pub fn to_case_spec(&self) -> AetsAdversarialCaseSpec {
        AetsAdversarialCaseSpec::new(
            self.scenario,
            self.host,
            self.resource,
            self.commands.clone(),
            self.limits,
        )
    }

    pub fn input_sha256(&self) -> Result<String, AetsCounterexampleError> {
        Ok(self.artifact()?.input_sha256)
    }

    fn artifact(&self) -> Result<AetsCounterexampleInputArtifact, AetsCounterexampleError> {
        let commands: Vec<CommandArtifact> =
            self.commands.iter().map(CommandArtifact::from).collect();
        let limits = LimitsArtifact::from(self.limits);
        let scenario_axis = scenario_name(self.scenario).to_owned();
        let host_axis = host_name(self.host).to_owned();
        let resource_axis = resource_name(self.resource).to_owned();
        let input_sha256 = input_sha256(
            &scenario_axis,
            &host_axis,
            &resource_axis,
            &commands,
            &limits,
        )?;
        Ok(AetsCounterexampleInputArtifact {
            scenario_axis,
            host_axis,
            resource_axis,
            commands,
            limits,
            input_sha256,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandArtifact {
    pub family_code: u8,
    pub kind_code: u8,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

impl From<&ContextCommand> for CommandArtifact {
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
pub struct LimitsArtifact {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

impl From<ExecutionLimits> for LimitsArtifact {
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
pub struct AetsCounterexampleInputArtifact {
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub commands: Vec<CommandArtifact>,
    pub limits: LimitsArtifact,
    pub input_sha256: String,
}

impl AetsCounterexampleInputArtifact {
    fn validate(&self) -> Result<(), AetsCounterexampleError> {
        if !SCENARIO_NAMES.contains(&self.scenario_axis.as_str())
            || !HOST_NAMES.contains(&self.host_axis.as_str())
            || !RESOURCE_NAMES.contains(&self.resource_axis.as_str())
            || self.commands.len() < 2
            || self.commands.last().map(|command| command.family_code) != Some(11)
            || self.commands[..self.commands.len() - 1]
                .iter()
                .any(|command| command.family_code == 11)
            || self
                .commands
                .iter()
                .any(|command| command.family_code > 11 || command.kind_code > 4)
            || self.limits.fuel == 0
            || self.limits.max_memory_pages == 0
            || self.limits.max_host_calls == 0
            || self.limits.timeout_ms == 0
        {
            return Err(AetsCounterexampleError::InputContract);
        }
        let expected = input_sha256(
            &self.scenario_axis,
            &self.host_axis,
            &self.resource_axis,
            &self.commands,
            &self.limits,
        )?;
        if self.input_sha256 != expected {
            return Err(AetsCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AetsComparisonSignature {
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
pub enum AetsDifferenceOrigin {
    SourceRefinement,
    DifferentialOracle {
        counterexample_kind: DifferentialCounterexampleKind,
        left_participant: String,
        right_participant: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsDifferenceSignature {
    pub origin: AetsDifferenceOrigin,
    pub comparison: AetsComparisonSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AetsShrinkOperation {
    RemoveCommand { index: u32 },
    ZeroPayloadTag { index: u32 },
    ZeroFault { index: u32 },
    ZeroServiceAlias { index: u32 },
    ZeroPublicSlot { index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AetsShrinkOutcome {
    Preserved,
    NotCounterexample,
    DifferentTypedDifference,
    EvaluationError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsShrinkAttempt {
    pub ordinal: u32,
    pub operation: AetsShrinkOperation,
    pub before_input_sha256: String,
    pub candidate_input_sha256: String,
    pub outcome: AetsShrinkOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsCounterexampleCaseArtifact {
    pub input: AetsCounterexampleInputArtifact,
    pub result_sha256: String,
    pub result: AetsMatrixCaseArtifact,
}

impl AetsCounterexampleCaseArtifact {
    fn new(
        input: &AetsCounterexampleInput,
        result: AetsMatrixCaseArtifact,
    ) -> Result<Self, AetsCounterexampleError> {
        validate_case_result(&result)?;
        Ok(Self {
            input: input.artifact()?,
            result_sha256: case_result_sha256(&result)?,
            result,
        })
    }

    fn validate(&self) -> Result<(), AetsCounterexampleError> {
        self.input.validate()?;
        validate_case_result(&self.result)?;
        if self.result_sha256 != case_result_sha256(&self.result)? {
            return Err(AetsCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsCounterexampleBundle {
    pub schema_version: String,
    pub shrinker_version: String,
    pub matrix_digest_sha256: String,
    pub hardware_status: String,
    pub shrink_order: Vec<String>,
    pub difference_signature: AetsDifferenceSignature,
    pub original_first_difference: ComparisonPoint,
    pub minimized_first_difference: ComparisonPoint,
    pub original: AetsCounterexampleCaseArtifact,
    pub minimized: AetsCounterexampleCaseArtifact,
    pub attempts: Vec<AetsShrinkAttempt>,
}

impl AetsCounterexampleBundle {
    pub fn validate(&self) -> Result<(), AetsCounterexampleError> {
        if self.schema_version != AETS_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.shrinker_version != AETS_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || self.shrink_order != shrink_order()
        {
            return Err(AetsCounterexampleError::ArtifactContract);
        }
        self.original.validate()?;
        self.minimized.validate()?;
        if self.original.result.verdict != AetsDifferentialVerdict::Counterexample
            || self.minimized.result.verdict != AetsDifferentialVerdict::Counterexample
        {
            return Err(AetsCounterexampleError::OriginalNotCounterexample);
        }
        let (original_signature, original_point) =
            first_typed_difference(&self.original.result.differential)?;
        let (minimized_signature, minimized_point) =
            first_typed_difference(&self.minimized.result.differential)?;
        if original_signature != self.difference_signature
            || minimized_signature != self.difference_signature
            || original_point != self.original_first_difference
            || minimized_point != self.minimized_first_difference
        {
            return Err(AetsCounterexampleError::ArtifactContract);
        }
        let mut current = self.original.input.input_sha256.as_str();
        for (index, attempt) in self.attempts.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| AetsCounterexampleError::Arithmetic)?;
            if attempt.ordinal != ordinal
                || attempt.before_input_sha256 != current
                || !is_sha256(&attempt.candidate_input_sha256)
                || attempt.candidate_input_sha256 == attempt.before_input_sha256
            {
                return Err(AetsCounterexampleError::ArtifactContract);
            }
            if attempt.outcome == AetsShrinkOutcome::Preserved {
                current = &attempt.candidate_input_sha256;
            }
        }
        if current != self.minimized.input.input_sha256 {
            return Err(AetsCounterexampleError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AetsCounterexampleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AetsCounterexampleError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AetsCounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn shrink_aets_counterexample<F, E>(
    matrix_digest_sha256: String,
    original_input: AetsCounterexampleInput,
    observed: AetsMatrixCaseArtifact,
    mut evaluator: F,
) -> Result<AetsCounterexampleBundle, AetsCounterexampleError>
where
    F: FnMut(&AetsCounterexampleInput) -> Result<AetsMatrixCaseArtifact, E>,
    E: Display,
{
    if !is_sha256(&matrix_digest_sha256) {
        return Err(AetsCounterexampleError::InvalidSha256);
    }
    validate_case_result(&observed)?;
    if observed.verdict != AetsDifferentialVerdict::Counterexample {
        return Err(AetsCounterexampleError::OriginalNotCounterexample);
    }
    let reproduced = evaluator(&original_input)
        .map_err(|error| AetsCounterexampleError::Evaluation(error.to_string()))?;
    validate_case_result(&reproduced)?;
    if reproduced != observed {
        return Err(AetsCounterexampleError::OriginalReproductionMismatch);
    }
    let (difference_signature, original_first_difference) =
        first_typed_difference(&observed.differential)?;
    let mut state = ShrinkState {
        input: original_input.clone(),
        result: observed.clone(),
        first_difference: original_first_difference.clone(),
    };
    let mut attempts = Vec::new();

    let mut index = state.input.commands.len() - 1;
    while index > 0 && state.input.commands.len() > 2 {
        index -= 1;
        if index >= state.input.commands.len() - 1 {
            continue;
        }
        let mut candidate = state.input.clone();
        candidate.commands.remove(index);
        try_candidate(
            candidate,
            AetsShrinkOperation::RemoveCommand {
                index: index_u32(index)?,
            },
            &difference_signature,
            &mut evaluator,
            &mut state,
            &mut attempts,
        )?;
    }

    for index in 0..state.input.commands.len() - 1 {
        if state.input.commands[index].payload_tag != 0 {
            let mut candidate = state.input.clone();
            candidate.commands[index].payload_tag = 0;
            try_candidate(
                candidate,
                AetsShrinkOperation::ZeroPayloadTag {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }
    for index in 0..state.input.commands.len() - 1 {
        if state.input.commands[index].fault != 0 {
            let mut candidate = state.input.clone();
            candidate.commands[index].fault = 0;
            try_candidate(
                candidate,
                AetsShrinkOperation::ZeroFault {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }
    for index in 0..state.input.commands.len() - 1 {
        if state.input.commands[index].service_alias != 0 {
            let mut candidate = state.input.clone();
            candidate.commands[index].service_alias = 0;
            try_candidate(
                candidate,
                AetsShrinkOperation::ZeroServiceAlias {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }
    for index in 0..state.input.commands.len() - 1 {
        if state.input.commands[index].public_slot != 0 {
            let mut candidate = state.input.clone();
            candidate.commands[index].public_slot = 0;
            try_candidate(
                candidate,
                AetsShrinkOperation::ZeroPublicSlot {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }

    let bundle = AetsCounterexampleBundle {
        schema_version: AETS_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        shrinker_version: AETS_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        matrix_digest_sha256,
        hardware_status: HARDWARE_STATUS.to_owned(),
        shrink_order: shrink_order(),
        difference_signature,
        original_first_difference,
        minimized_first_difference: state.first_difference,
        original: AetsCounterexampleCaseArtifact::new(&original_input, observed)?,
        minimized: AetsCounterexampleCaseArtifact::new(&state.input, state.result)?,
        attempts,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn verify_aets_counterexample_bundle_with<F, E>(
    bundle: &AetsCounterexampleBundle,
    matrix_digest_sha256: String,
    original_input: AetsCounterexampleInput,
    observed: AetsMatrixCaseArtifact,
    evaluator: F,
) -> Result<(), AetsCounterexampleError>
where
    F: FnMut(&AetsCounterexampleInput) -> Result<AetsMatrixCaseArtifact, E>,
    E: Display,
{
    bundle.validate()?;
    let recomputed =
        shrink_aets_counterexample(matrix_digest_sha256, original_input, observed, evaluator)?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AetsCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

pub fn build_aets_counterexample_bundle(
    compiled: &AetsCompiledQsm,
    matrix: &AetsAdversarialMatrix,
    execution: &AetsMatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AetsMatrixLimits,
    engine_digests: &AetsEngineDigests,
) -> Result<AetsCounterexampleBundle, AetsCounterexampleError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| AetsCounterexampleError::Matrix(error.to_string()))?;
    execution
        .validate()
        .map_err(|error| AetsCounterexampleError::MatrixExecution(error.to_string()))?;
    let matrix_digest_sha256 = matrix.matrix_digest().to_hex();
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| AetsCounterexampleError::Matrix(error.to_string()))?;
    if execution.matrix_digest_sha256 != matrix_digest_sha256
        || execution.matrix_bytes_sha256 != sha256_hex(&matrix_bytes)
    {
        return Err(AetsCounterexampleError::MatrixBinding);
    }
    let original_case = matrix
        .cases()
        .iter()
        .find(|case| case.case_id().to_hex() == original_case_id_sha256)
        .ok_or(AetsCounterexampleError::CaseNotFound)?;
    let observed = execution
        .cases
        .iter()
        .find(|case| case.case_id_sha256 == original_case_id_sha256)
        .cloned()
        .ok_or(AetsCounterexampleError::CaseResultNotFound)?;
    let original_input = AetsCounterexampleInput::from_case(original_case)?;
    shrink_aets_counterexample(
        matrix_digest_sha256,
        original_input,
        observed,
        |candidate| {
            evaluate_candidate(
                compiled,
                matrix.seed(),
                candidate,
                matrix_limits,
                engine_digests,
            )
        },
    )
}

pub fn verify_aets_counterexample_bundle(
    bundle: &AetsCounterexampleBundle,
    compiled: &AetsCompiledQsm,
    matrix: &AetsAdversarialMatrix,
    execution: &AetsMatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AetsMatrixLimits,
    engine_digests: &AetsEngineDigests,
) -> Result<(), AetsCounterexampleError> {
    bundle.validate()?;
    let recomputed = build_aets_counterexample_bundle(
        compiled,
        matrix,
        execution,
        original_case_id_sha256,
        matrix_limits,
        engine_digests,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AetsCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

struct ShrinkState {
    input: AetsCounterexampleInput,
    result: AetsMatrixCaseArtifact,
    first_difference: ComparisonPoint,
}

fn try_candidate<F, E>(
    candidate: AetsCounterexampleInput,
    operation: AetsShrinkOperation,
    expected_signature: &AetsDifferenceSignature,
    evaluator: &mut F,
    state: &mut ShrinkState,
    attempts: &mut Vec<AetsShrinkAttempt>,
) -> Result<(), AetsCounterexampleError>
where
    F: FnMut(&AetsCounterexampleInput) -> Result<AetsMatrixCaseArtifact, E>,
    E: Display,
{
    let before_input_sha256 = state.input.input_sha256()?;
    let candidate_input_sha256 = candidate.input_sha256()?;
    let mut accepted = None;
    let outcome = match evaluator(&candidate) {
        Err(_) => AetsShrinkOutcome::EvaluationError,
        Ok(result) if validate_case_result(&result).is_err() => AetsShrinkOutcome::EvaluationError,
        Ok(result) if result.verdict != AetsDifferentialVerdict::Counterexample => {
            AetsShrinkOutcome::NotCounterexample
        }
        Ok(result) => match first_typed_difference(&result.differential) {
            Ok((signature, point)) if signature == *expected_signature => {
                accepted = Some((result, point));
                AetsShrinkOutcome::Preserved
            }
            Ok(_) => AetsShrinkOutcome::DifferentTypedDifference,
            Err(_) => AetsShrinkOutcome::EvaluationError,
        },
    };
    attempts.push(AetsShrinkAttempt {
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

fn evaluate_candidate(
    compiled: &AetsCompiledQsm,
    seed: crate::AetsMatrixSeed,
    input: &AetsCounterexampleInput,
    matrix_limits: AetsMatrixLimits,
    engine_digests: &AetsEngineDigests,
) -> Result<AetsMatrixCaseArtifact, String> {
    let candidate_matrix =
        AetsAdversarialMatrix::new(compiled, seed, vec![input.to_case_spec()], matrix_limits)
            .map_err(|error| error.to_string())?;
    let execution = evaluate_aets_adversarial_matrix(
        compiled,
        &candidate_matrix,
        matrix_limits,
        engine_digests,
    )
    .map_err(|error| error.to_string())?;
    execution
        .cases
        .into_iter()
        .next()
        .ok_or_else(|| "candidate matrix produced no case artifact".to_owned())
}

fn first_typed_difference(
    artifact: &AetsDifferentialArtifact,
) -> Result<(AetsDifferenceSignature, ComparisonPoint), AetsCounterexampleError> {
    artifact
        .validate()
        .map_err(|error| AetsCounterexampleError::Differential(error.to_string()))?;
    if artifact.source_refinement.verdict == AetsDifferentialVerdict::Counterexample {
        let point = artifact
            .source_refinement
            .first_difference
            .clone()
            .ok_or(AetsCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AetsDifferenceSignature {
                origin: AetsDifferenceOrigin::SourceRefinement,
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
            .ok_or(AetsCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AetsDifferenceSignature {
                origin: AetsDifferenceOrigin::DifferentialOracle {
                    counterexample_kind: counterexample.kind,
                    left_participant: counterexample.left_participant.clone(),
                    right_participant: counterexample.right_participant.clone(),
                },
                comparison: comparison_signature(&counterexample.first_difference),
            },
            counterexample.first_difference.clone(),
        ));
    }
    Err(AetsCounterexampleError::MissingFirstDifference)
}

fn comparison_signature(point: &ComparisonPoint) -> AetsComparisonSignature {
    match point {
        ComparisonPoint::Trace {
            left_axis,
            right_axis,
            ..
        } => AetsComparisonSignature::Trace {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
        ComparisonPoint::Termination {
            left_axis,
            right_axis,
            ..
        } => AetsComparisonSignature::Termination {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
    }
}

fn validate_case_result(result: &AetsMatrixCaseArtifact) -> Result<(), AetsCounterexampleError> {
    if !is_sha256(&result.case_id_sha256)
        || result.scenario_axis.is_empty()
        || result.host_axis.is_empty()
        || result.resource_axis.is_empty()
    {
        return Err(AetsCounterexampleError::ArtifactContract);
    }
    result
        .differential
        .validate()
        .map_err(|error| AetsCounterexampleError::Differential(error.to_string()))?;
    let expected = if result.injection == AetsHostInjection::NotApplicable {
        AetsDifferentialVerdict::Unresolved
    } else {
        result.differential.verdict
    };
    if result.verdict != expected {
        return Err(AetsCounterexampleError::ArtifactContract);
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
) -> Result<(), AetsCounterexampleError> {
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
        return Err(AetsCounterexampleError::InputContract);
    }
    Ok(())
}

#[derive(Serialize)]
struct InputBody<'a> {
    schema_version: &'static str,
    scenario_axis: &'a str,
    host_axis: &'a str,
    resource_axis: &'a str,
    commands: &'a [CommandArtifact],
    limits: &'a LimitsArtifact,
}

fn input_sha256(
    scenario_axis: &str,
    host_axis: &str,
    resource_axis: &str,
    commands: &[CommandArtifact],
    limits: &LimitsArtifact,
) -> Result<String, AetsCounterexampleError> {
    let bytes = serde_json::to_vec(&InputBody {
        schema_version: AETS_COUNTEREXAMPLE_BUNDLE_VERSION,
        scenario_axis,
        host_axis,
        resource_axis,
        commands,
        limits,
    })
    .map_err(|error| AetsCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn case_result_sha256(result: &AetsMatrixCaseArtifact) -> Result<String, AetsCounterexampleError> {
    validate_case_result(result)?;
    let bytes = serde_json::to_vec(result)
        .map_err(|error| AetsCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn shrink_order() -> Vec<String> {
    SHRINK_ORDER.iter().map(|step| (*step).to_owned()).collect()
}

fn index_u32(index: usize) -> Result<u32, AetsCounterexampleError> {
    u32::try_from(index).map_err(|_| AetsCounterexampleError::Arithmetic)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const SCENARIO_NAMES: [&str; 10] = [
    "NORMAL",
    "RESET",
    "HANDOFF",
    "DEADLINE_BEFORE",
    "DEADLINE_AT",
    "DEADLINE_AFTER",
    "UNKNOWN_SERVICE",
    "PUBLIC_FAULT_TIMEOUT",
    "PUBLIC_FAULT_RECONNECT",
    "PUBLIC_FAULT_LOSS",
];
const HOST_NAMES: [&str; 5] = ["CONTINUE", "TERMINATE", "TIMEOUT", "RECONNECT", "LOSS"];
const RESOURCE_NAMES: [&str; 4] = [
    "NOMINAL",
    "FUEL_BOUNDARY",
    "MEMORY_BOUNDARY",
    "HOST_CALL_BOUNDARY",
];

fn scenario_name(value: AetsScenarioAxis) -> &'static str {
    match value {
        AetsScenarioAxis::Normal => "NORMAL",
        AetsScenarioAxis::Reset => "RESET",
        AetsScenarioAxis::Handoff => "HANDOFF",
        AetsScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        AetsScenarioAxis::DeadlineAt => "DEADLINE_AT",
        AetsScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        AetsScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
        AetsScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        AetsScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        AetsScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
    }
}

fn host_name(value: AetsHostAxis) -> &'static str {
    match value {
        AetsHostAxis::Continue => "CONTINUE",
        AetsHostAxis::Terminate => "TERMINATE",
        AetsHostAxis::Timeout => "TIMEOUT",
        AetsHostAxis::Reconnect => "RECONNECT",
        AetsHostAxis::Loss => "LOSS",
    }
}

fn resource_name(value: AetsResourceAxis) -> &'static str {
    match value {
        AetsResourceAxis::Nominal => "NOMINAL",
        AetsResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        AetsResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        AetsResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
    }
}

#[derive(Debug, Error)]
pub enum AetsCounterexampleError {
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
    #[error("matrix bytes and execution artifact are not bound")]
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
    #[error("counterexample serialization failed: {0}")]
    Serialization(String),
    #[error("counterexample arithmetic overflow")]
    Arithmetic,
}
