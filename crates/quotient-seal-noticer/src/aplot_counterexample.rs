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
    evaluate_aplot_adversarial_matrix, AplotAdversarialCase, AplotAdversarialCaseSpec,
    AplotAdversarialMatrix, AplotCompiledQsm, AplotDifferentialArtifact, AplotDifferentialVerdict,
    AplotEngineDigests, AplotHostAxis, AplotHostInjection, AplotMatrixCaseArtifact,
    AplotMatrixExecutionArtifact, AplotMatrixLimits, AplotResourceAxis, AplotScenarioAxis,
};

pub const APLOT_COUNTEREXAMPLE_BUNDLE_VERSION: &str = "noticer-aplot-counterexample-bundle/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const SHRINK_ORDER: [&str; 5] = [
    "REMOVE_NON_STOP_COMMANDS_REVERSE_INDEX_KEEP_ONE",
    "ZERO_PAYLOAD_TAG_ASCENDING_INDEX",
    "ZERO_FAULT_ASCENDING_INDEX",
    "ZERO_SERVICE_ALIAS_ASCENDING_INDEX",
    "ZERO_PUBLIC_SLOT_ASCENDING_INDEX",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotCounterexampleInput {
    scenario: AplotScenarioAxis,
    host: AplotHostAxis,
    resource: AplotResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AplotCounterexampleInput {
    pub fn new(
        scenario: AplotScenarioAxis,
        host: AplotHostAxis,
        resource: AplotResourceAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Result<Self, AplotCounterexampleError> {
        validate_commands(&commands, limits)?;
        Ok(Self {
            scenario,
            host,
            resource,
            commands,
            limits,
        })
    }

    pub fn from_case(case: &AplotAdversarialCase) -> Result<Self, AplotCounterexampleError> {
        Self::new(
            case.scenario(),
            case.host(),
            case.resource(),
            case.commands().to_vec(),
            case.limits(),
        )
    }

    #[must_use]
    pub const fn scenario(&self) -> AplotScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn host(&self) -> AplotHostAxis {
        self.host
    }

    #[must_use]
    pub const fn resource(&self) -> AplotResourceAxis {
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
    pub fn to_case_spec(&self) -> AplotAdversarialCaseSpec {
        AplotAdversarialCaseSpec::new(
            self.scenario,
            self.host,
            self.resource,
            self.commands.clone(),
            self.limits,
        )
    }

    pub fn input_sha256(&self) -> Result<String, AplotCounterexampleError> {
        Ok(self.artifact()?.input_sha256)
    }

    fn artifact(&self) -> Result<AplotCounterexampleInputArtifact, AplotCounterexampleError> {
        let commands: Vec<AplotCommandArtifact> = self
            .commands
            .iter()
            .map(AplotCommandArtifact::from)
            .collect();
        let limits = AplotLimitsArtifact::from(self.limits);
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
        Ok(AplotCounterexampleInputArtifact {
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
pub struct AplotCommandArtifact {
    pub family_code: u8,
    pub kind_code: u8,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

impl From<&ContextCommand> for AplotCommandArtifact {
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
pub struct AplotLimitsArtifact {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

impl From<ExecutionLimits> for AplotLimitsArtifact {
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
pub struct AplotCounterexampleInputArtifact {
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub commands: Vec<AplotCommandArtifact>,
    pub limits: AplotLimitsArtifact,
    pub input_sha256: String,
}

impl AplotCounterexampleInputArtifact {
    fn validate(&self) -> Result<(), AplotCounterexampleError> {
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
            return Err(AplotCounterexampleError::InputContract);
        }
        let expected = input_sha256(
            &self.scenario_axis,
            &self.host_axis,
            &self.resource_axis,
            &self.commands,
            &self.limits,
        )?;
        if self.input_sha256 != expected {
            return Err(AplotCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AplotComparisonSignature {
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
pub enum AplotDifferenceOrigin {
    SourceRefinement,
    DifferentialOracle {
        counterexample_kind: DifferentialCounterexampleKind,
        left_participant: String,
        right_participant: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotDifferenceSignature {
    pub origin: AplotDifferenceOrigin,
    pub comparison: AplotComparisonSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AplotShrinkOperation {
    RemoveCommand { index: u32 },
    ZeroPayloadTag { index: u32 },
    ZeroFault { index: u32 },
    ZeroServiceAlias { index: u32 },
    ZeroPublicSlot { index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AplotShrinkOutcome {
    Preserved,
    NotCounterexample,
    DifferentTypedDifference,
    EvaluationError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotShrinkAttempt {
    pub ordinal: u32,
    pub operation: AplotShrinkOperation,
    pub before_input_sha256: String,
    pub candidate_input_sha256: String,
    pub outcome: AplotShrinkOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotCounterexampleCaseArtifact {
    pub input: AplotCounterexampleInputArtifact,
    pub result_sha256: String,
    pub result: AplotMatrixCaseArtifact,
}

impl AplotCounterexampleCaseArtifact {
    fn new(
        input: &AplotCounterexampleInput,
        result: AplotMatrixCaseArtifact,
    ) -> Result<Self, AplotCounterexampleError> {
        validate_case_result(&result)?;
        Ok(Self {
            input: input.artifact()?,
            result_sha256: case_result_sha256(&result)?,
            result,
        })
    }

    fn validate(&self) -> Result<(), AplotCounterexampleError> {
        self.input.validate()?;
        validate_case_result(&self.result)?;
        if self.result_sha256 != case_result_sha256(&self.result)? {
            return Err(AplotCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AplotCounterexampleBundle {
    pub schema_version: String,
    pub shrinker_version: String,
    pub matrix_digest_sha256: String,
    pub hardware_status: String,
    pub shrink_order: Vec<String>,
    pub difference_signature: AplotDifferenceSignature,
    pub original_first_difference: ComparisonPoint,
    pub minimized_first_difference: ComparisonPoint,
    pub original: AplotCounterexampleCaseArtifact,
    pub minimized: AplotCounterexampleCaseArtifact,
    pub attempts: Vec<AplotShrinkAttempt>,
}

impl AplotCounterexampleBundle {
    pub fn validate(&self) -> Result<(), AplotCounterexampleError> {
        if self.schema_version != APLOT_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.shrinker_version != APLOT_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || self.shrink_order != shrink_order()
        {
            return Err(AplotCounterexampleError::ArtifactContract);
        }
        self.original.validate()?;
        self.minimized.validate()?;
        if self.original.result.verdict != AplotDifferentialVerdict::Counterexample
            || self.minimized.result.verdict != AplotDifferentialVerdict::Counterexample
        {
            return Err(AplotCounterexampleError::OriginalNotCounterexample);
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
            return Err(AplotCounterexampleError::ArtifactContract);
        }
        let mut current = self.original.input.input_sha256.as_str();
        for (index, attempt) in self.attempts.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| AplotCounterexampleError::Arithmetic)?;
            if attempt.ordinal != ordinal
                || attempt.before_input_sha256 != current
                || !is_sha256(&attempt.candidate_input_sha256)
                || attempt.candidate_input_sha256 == attempt.before_input_sha256
            {
                return Err(AplotCounterexampleError::ArtifactContract);
            }
            if attempt.outcome == AplotShrinkOutcome::Preserved {
                current = &attempt.candidate_input_sha256;
            }
        }
        if current != self.minimized.input.input_sha256 {
            return Err(AplotCounterexampleError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AplotCounterexampleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AplotCounterexampleError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AplotCounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn shrink_aplot_counterexample<F, E>(
    matrix_digest_sha256: String,
    original_input: AplotCounterexampleInput,
    observed: AplotMatrixCaseArtifact,
    mut evaluator: F,
) -> Result<AplotCounterexampleBundle, AplotCounterexampleError>
where
    F: FnMut(&AplotCounterexampleInput) -> Result<AplotMatrixCaseArtifact, E>,
    E: Display,
{
    if !is_sha256(&matrix_digest_sha256) {
        return Err(AplotCounterexampleError::InvalidSha256);
    }
    validate_case_result(&observed)?;
    if observed.verdict != AplotDifferentialVerdict::Counterexample {
        return Err(AplotCounterexampleError::OriginalNotCounterexample);
    }
    let reproduced = evaluator(&original_input)
        .map_err(|error| AplotCounterexampleError::Evaluation(error.to_string()))?;
    validate_case_result(&reproduced)?;
    if reproduced != observed {
        return Err(AplotCounterexampleError::OriginalReproductionMismatch);
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
            AplotShrinkOperation::RemoveCommand {
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
                AplotShrinkOperation::ZeroPayloadTag {
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
                AplotShrinkOperation::ZeroFault {
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
                AplotShrinkOperation::ZeroServiceAlias {
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
                AplotShrinkOperation::ZeroPublicSlot {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }

    let bundle = AplotCounterexampleBundle {
        schema_version: APLOT_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        shrinker_version: APLOT_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        matrix_digest_sha256,
        hardware_status: HARDWARE_STATUS.to_owned(),
        shrink_order: shrink_order(),
        difference_signature,
        original_first_difference,
        minimized_first_difference: state.first_difference,
        original: AplotCounterexampleCaseArtifact::new(&original_input, observed)?,
        minimized: AplotCounterexampleCaseArtifact::new(&state.input, state.result)?,
        attempts,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn verify_aplot_counterexample_bundle_with<F, E>(
    bundle: &AplotCounterexampleBundle,
    matrix_digest_sha256: String,
    original_input: AplotCounterexampleInput,
    observed: AplotMatrixCaseArtifact,
    evaluator: F,
) -> Result<(), AplotCounterexampleError>
where
    F: FnMut(&AplotCounterexampleInput) -> Result<AplotMatrixCaseArtifact, E>,
    E: Display,
{
    bundle.validate()?;
    let recomputed =
        shrink_aplot_counterexample(matrix_digest_sha256, original_input, observed, evaluator)?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AplotCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

pub fn build_aplot_counterexample_bundle(
    compiled: &AplotCompiledQsm,
    matrix: &AplotAdversarialMatrix,
    execution: &AplotMatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AplotMatrixLimits,
    engine_digests: &AplotEngineDigests,
) -> Result<AplotCounterexampleBundle, AplotCounterexampleError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| AplotCounterexampleError::Matrix(error.to_string()))?;
    execution
        .validate()
        .map_err(|error| AplotCounterexampleError::MatrixExecution(error.to_string()))?;
    let matrix_digest_sha256 = matrix.matrix_digest().to_hex();
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| AplotCounterexampleError::Matrix(error.to_string()))?;
    if execution.matrix_digest_sha256 != matrix_digest_sha256
        || execution.matrix_bytes_sha256 != sha256_hex(&matrix_bytes)
    {
        return Err(AplotCounterexampleError::MatrixBinding);
    }
    let original_case = matrix
        .cases()
        .iter()
        .find(|case| case.case_id().to_hex() == original_case_id_sha256)
        .ok_or(AplotCounterexampleError::CaseNotFound)?;
    let observed = execution
        .cases
        .iter()
        .find(|case| case.case_id_sha256 == original_case_id_sha256)
        .cloned()
        .ok_or(AplotCounterexampleError::CaseResultNotFound)?;
    let original_input = AplotCounterexampleInput::from_case(original_case)?;
    shrink_aplot_counterexample(
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

pub fn verify_aplot_counterexample_bundle(
    bundle: &AplotCounterexampleBundle,
    compiled: &AplotCompiledQsm,
    matrix: &AplotAdversarialMatrix,
    execution: &AplotMatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: AplotMatrixLimits,
    engine_digests: &AplotEngineDigests,
) -> Result<(), AplotCounterexampleError> {
    bundle.validate()?;
    let recomputed = build_aplot_counterexample_bundle(
        compiled,
        matrix,
        execution,
        original_case_id_sha256,
        matrix_limits,
        engine_digests,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(AplotCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

struct ShrinkState {
    input: AplotCounterexampleInput,
    result: AplotMatrixCaseArtifact,
    first_difference: ComparisonPoint,
}

fn try_candidate<F, E>(
    candidate: AplotCounterexampleInput,
    operation: AplotShrinkOperation,
    expected_signature: &AplotDifferenceSignature,
    evaluator: &mut F,
    state: &mut ShrinkState,
    attempts: &mut Vec<AplotShrinkAttempt>,
) -> Result<(), AplotCounterexampleError>
where
    F: FnMut(&AplotCounterexampleInput) -> Result<AplotMatrixCaseArtifact, E>,
    E: Display,
{
    let before_input_sha256 = state.input.input_sha256()?;
    let candidate_input_sha256 = candidate.input_sha256()?;
    let mut accepted = None;
    let outcome = match evaluator(&candidate) {
        Err(_) => AplotShrinkOutcome::EvaluationError,
        Ok(result) if validate_case_result(&result).is_err() => AplotShrinkOutcome::EvaluationError,
        Ok(result) if result.verdict != AplotDifferentialVerdict::Counterexample => {
            AplotShrinkOutcome::NotCounterexample
        }
        Ok(result) => match first_typed_difference(&result.differential) {
            Ok((signature, point)) if signature == *expected_signature => {
                accepted = Some((result, point));
                AplotShrinkOutcome::Preserved
            }
            Ok(_) => AplotShrinkOutcome::DifferentTypedDifference,
            Err(_) => AplotShrinkOutcome::EvaluationError,
        },
    };
    attempts.push(AplotShrinkAttempt {
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
    compiled: &AplotCompiledQsm,
    seed: crate::AplotMatrixSeed,
    input: &AplotCounterexampleInput,
    matrix_limits: AplotMatrixLimits,
    engine_digests: &AplotEngineDigests,
) -> Result<AplotMatrixCaseArtifact, String> {
    let candidate_matrix =
        AplotAdversarialMatrix::new(compiled, seed, vec![input.to_case_spec()], matrix_limits)
            .map_err(|error| error.to_string())?;
    let execution = evaluate_aplot_adversarial_matrix(
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
    artifact: &AplotDifferentialArtifact,
) -> Result<(AplotDifferenceSignature, ComparisonPoint), AplotCounterexampleError> {
    artifact
        .validate()
        .map_err(|error| AplotCounterexampleError::Differential(error.to_string()))?;
    if artifact.source_refinement.verdict == AplotDifferentialVerdict::Counterexample {
        let point = artifact
            .source_refinement
            .first_difference
            .clone()
            .ok_or(AplotCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AplotDifferenceSignature {
                origin: AplotDifferenceOrigin::SourceRefinement,
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
            .ok_or(AplotCounterexampleError::MissingFirstDifference)?;
        return Ok((
            AplotDifferenceSignature {
                origin: AplotDifferenceOrigin::DifferentialOracle {
                    counterexample_kind: counterexample.kind,
                    left_participant: counterexample.left_participant.clone(),
                    right_participant: counterexample.right_participant.clone(),
                },
                comparison: comparison_signature(&counterexample.first_difference),
            },
            counterexample.first_difference.clone(),
        ));
    }
    Err(AplotCounterexampleError::MissingFirstDifference)
}

fn comparison_signature(point: &ComparisonPoint) -> AplotComparisonSignature {
    match point {
        ComparisonPoint::Trace {
            left_axis,
            right_axis,
            ..
        } => AplotComparisonSignature::Trace {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
        ComparisonPoint::Termination {
            left_axis,
            right_axis,
            ..
        } => AplotComparisonSignature::Termination {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
    }
}

fn validate_case_result(result: &AplotMatrixCaseArtifact) -> Result<(), AplotCounterexampleError> {
    if !is_sha256(&result.case_id_sha256)
        || result.scenario_axis.is_empty()
        || result.host_axis.is_empty()
        || result.resource_axis.is_empty()
    {
        return Err(AplotCounterexampleError::ArtifactContract);
    }
    result
        .differential
        .validate()
        .map_err(|error| AplotCounterexampleError::Differential(error.to_string()))?;
    let expected = if result.injection == AplotHostInjection::NotApplicable {
        AplotDifferentialVerdict::Unresolved
    } else {
        result.differential.verdict
    };
    if result.verdict != expected {
        return Err(AplotCounterexampleError::ArtifactContract);
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
) -> Result<(), AplotCounterexampleError> {
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
        return Err(AplotCounterexampleError::InputContract);
    }
    Ok(())
}

#[derive(Serialize)]
struct InputBody<'a> {
    schema_version: &'static str,
    scenario_axis: &'a str,
    host_axis: &'a str,
    resource_axis: &'a str,
    commands: &'a [AplotCommandArtifact],
    limits: &'a AplotLimitsArtifact,
}

fn input_sha256(
    scenario_axis: &str,
    host_axis: &str,
    resource_axis: &str,
    commands: &[AplotCommandArtifact],
    limits: &AplotLimitsArtifact,
) -> Result<String, AplotCounterexampleError> {
    let bytes = serde_json::to_vec(&InputBody {
        schema_version: APLOT_COUNTEREXAMPLE_BUNDLE_VERSION,
        scenario_axis,
        host_axis,
        resource_axis,
        commands,
        limits,
    })
    .map_err(|error| AplotCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn case_result_sha256(
    result: &AplotMatrixCaseArtifact,
) -> Result<String, AplotCounterexampleError> {
    validate_case_result(result)?;
    let bytes = serde_json::to_vec(result)
        .map_err(|error| AplotCounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn shrink_order() -> Vec<String> {
    SHRINK_ORDER.iter().map(|step| (*step).to_owned()).collect()
}

fn index_u32(index: usize) -> Result<u32, AplotCounterexampleError> {
    u32::try_from(index).map_err(|_| AplotCounterexampleError::Arithmetic)
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

const SCENARIO_NAMES: [&str; 15] = [
    "NORMAL",
    "DECLARED_LOSS",
    "DECLARED_RECONNECT",
    "PUBLIC_FAULT_TIMEOUT",
    "PUBLIC_FAULT_RECONNECT",
    "PUBLIC_FAULT_LOSS",
    "DUPLICATE_STEP",
    "CAPACITY_BOUNDARY",
    "SECRET_RETRY_ATTEMPT",
    "RESET",
    "HANDOFF",
    "DEADLINE_BEFORE",
    "DEADLINE_AT",
    "DEADLINE_AFTER",
    "UNKNOWN_SERVICE",
];
const HOST_NAMES: [&str; 5] = ["CONTINUE", "TERMINATE", "TIMEOUT", "RECONNECT", "LOSS"];
const RESOURCE_NAMES: [&str; 4] = [
    "NOMINAL",
    "FUEL_BOUNDARY",
    "MEMORY_BOUNDARY",
    "HOST_CALL_BOUNDARY",
];

fn scenario_name(value: AplotScenarioAxis) -> &'static str {
    match value {
        AplotScenarioAxis::Normal => "NORMAL",
        AplotScenarioAxis::DeclaredLoss => "DECLARED_LOSS",
        AplotScenarioAxis::DeclaredReconnect => "DECLARED_RECONNECT",
        AplotScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        AplotScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        AplotScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
        AplotScenarioAxis::DuplicateStep => "DUPLICATE_STEP",
        AplotScenarioAxis::CapacityBoundary => "CAPACITY_BOUNDARY",
        AplotScenarioAxis::SecretRetryAttempt => "SECRET_RETRY_ATTEMPT",
        AplotScenarioAxis::Reset => "RESET",
        AplotScenarioAxis::Handoff => "HANDOFF",
        AplotScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        AplotScenarioAxis::DeadlineAt => "DEADLINE_AT",
        AplotScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        AplotScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
    }
}

fn host_name(value: AplotHostAxis) -> &'static str {
    match value {
        AplotHostAxis::Continue => "CONTINUE",
        AplotHostAxis::Terminate => "TERMINATE",
        AplotHostAxis::Timeout => "TIMEOUT",
        AplotHostAxis::Reconnect => "RECONNECT",
        AplotHostAxis::Loss => "LOSS",
    }
}

fn resource_name(value: AplotResourceAxis) -> &'static str {
    match value {
        AplotResourceAxis::Nominal => "NOMINAL",
        AplotResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        AplotResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        AplotResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
    }
}

#[derive(Debug, Error)]
pub enum AplotCounterexampleError {
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
