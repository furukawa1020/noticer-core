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
    evaluate_atv2_adversarial_matrix, Atv2AdversarialCase, Atv2AdversarialCaseSpec,
    Atv2AdversarialMatrix, Atv2CompiledQsm, Atv2DifferentialArtifact, Atv2DifferentialVerdict,
    Atv2EngineDigests, Atv2HostAxis, Atv2HostInjection, Atv2MatrixCaseArtifact,
    Atv2MatrixExecutionArtifact, Atv2MatrixLimits, Atv2ResourceAxis, Atv2ScenarioAxis,
};

pub const ATV2_COUNTEREXAMPLE_BUNDLE_VERSION: &str = "noticer-atv2-counterexample-bundle/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const SHRINK_ORDER: [&str; 5] = [
    "REMOVE_NON_STOP_COMMANDS_REVERSE_INDEX_KEEP_ONE",
    "ZERO_PAYLOAD_TAG_ASCENDING_INDEX",
    "ZERO_FAULT_ASCENDING_INDEX",
    "ZERO_SERVICE_ALIAS_ASCENDING_INDEX",
    "ZERO_PUBLIC_SLOT_ASCENDING_INDEX",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atv2CounterexampleInput {
    scenario: Atv2ScenarioAxis,
    host: Atv2HostAxis,
    resource: Atv2ResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl Atv2CounterexampleInput {
    pub fn new(
        scenario: Atv2ScenarioAxis,
        host: Atv2HostAxis,
        resource: Atv2ResourceAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Result<Self, Atv2CounterexampleError> {
        validate_commands(&commands, limits)?;
        Ok(Self {
            scenario,
            host,
            resource,
            commands,
            limits,
        })
    }

    pub fn from_case(case: &Atv2AdversarialCase) -> Result<Self, Atv2CounterexampleError> {
        Self::new(
            case.scenario(),
            case.host(),
            case.resource(),
            case.commands().to_vec(),
            case.limits(),
        )
    }

    #[must_use]
    pub const fn scenario(&self) -> Atv2ScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn host(&self) -> Atv2HostAxis {
        self.host
    }

    #[must_use]
    pub const fn resource(&self) -> Atv2ResourceAxis {
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
    pub fn to_case_spec(&self) -> Atv2AdversarialCaseSpec {
        Atv2AdversarialCaseSpec::new(
            self.scenario,
            self.host,
            self.resource,
            self.commands.clone(),
            self.limits,
        )
    }

    pub fn input_sha256(&self) -> Result<String, Atv2CounterexampleError> {
        Ok(self.artifact()?.input_sha256)
    }

    fn artifact(&self) -> Result<Atv2CounterexampleInputArtifact, Atv2CounterexampleError> {
        let commands: Vec<Atv2CommandArtifact> = self
            .commands
            .iter()
            .map(Atv2CommandArtifact::from)
            .collect();
        let limits = Atv2LimitsArtifact::from(self.limits);
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
        Ok(Atv2CounterexampleInputArtifact {
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
pub struct Atv2CommandArtifact {
    pub family_code: u8,
    pub kind_code: u8,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

impl From<&ContextCommand> for Atv2CommandArtifact {
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
pub struct Atv2LimitsArtifact {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

impl From<ExecutionLimits> for Atv2LimitsArtifact {
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
pub struct Atv2CounterexampleInputArtifact {
    pub scenario_axis: String,
    pub host_axis: String,
    pub resource_axis: String,
    pub commands: Vec<Atv2CommandArtifact>,
    pub limits: Atv2LimitsArtifact,
    pub input_sha256: String,
}

impl Atv2CounterexampleInputArtifact {
    fn validate(&self) -> Result<(), Atv2CounterexampleError> {
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
            return Err(Atv2CounterexampleError::InputContract);
        }
        let expected = input_sha256(
            &self.scenario_axis,
            &self.host_axis,
            &self.resource_axis,
            &self.commands,
            &self.limits,
        )?;
        if self.input_sha256 != expected {
            return Err(Atv2CounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Atv2ComparisonSignature {
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
pub enum Atv2DifferenceOrigin {
    SourceRefinement,
    DifferentialOracle {
        counterexample_kind: DifferentialCounterexampleKind,
        left_participant: String,
        right_participant: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2DifferenceSignature {
    pub origin: Atv2DifferenceOrigin,
    pub comparison: Atv2ComparisonSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Atv2ShrinkOperation {
    RemoveCommand { index: u32 },
    ZeroPayloadTag { index: u32 },
    ZeroFault { index: u32 },
    ZeroServiceAlias { index: u32 },
    ZeroPublicSlot { index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Atv2ShrinkOutcome {
    Preserved,
    NotCounterexample,
    DifferentTypedDifference,
    EvaluationError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2ShrinkAttempt {
    pub ordinal: u32,
    pub operation: Atv2ShrinkOperation,
    pub before_input_sha256: String,
    pub candidate_input_sha256: String,
    pub outcome: Atv2ShrinkOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2CounterexampleCaseArtifact {
    pub input: Atv2CounterexampleInputArtifact,
    pub result_sha256: String,
    pub result: Atv2MatrixCaseArtifact,
}

impl Atv2CounterexampleCaseArtifact {
    fn new(
        input: &Atv2CounterexampleInput,
        result: Atv2MatrixCaseArtifact,
    ) -> Result<Self, Atv2CounterexampleError> {
        validate_case_result(&result)?;
        Ok(Self {
            input: input.artifact()?,
            result_sha256: case_result_sha256(&result)?,
            result,
        })
    }

    fn validate(&self) -> Result<(), Atv2CounterexampleError> {
        self.input.validate()?;
        validate_case_result(&self.result)?;
        if self.result_sha256 != case_result_sha256(&self.result)? {
            return Err(Atv2CounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atv2CounterexampleBundle {
    pub schema_version: String,
    pub shrinker_version: String,
    pub matrix_digest_sha256: String,
    pub hardware_status: String,
    pub shrink_order: Vec<String>,
    pub difference_signature: Atv2DifferenceSignature,
    pub original_first_difference: ComparisonPoint,
    pub minimized_first_difference: ComparisonPoint,
    pub original: Atv2CounterexampleCaseArtifact,
    pub minimized: Atv2CounterexampleCaseArtifact,
    pub attempts: Vec<Atv2ShrinkAttempt>,
}

impl Atv2CounterexampleBundle {
    pub fn validate(&self) -> Result<(), Atv2CounterexampleError> {
        if self.schema_version != ATV2_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.shrinker_version != ATV2_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || self.shrink_order != shrink_order()
        {
            return Err(Atv2CounterexampleError::ArtifactContract);
        }
        self.original.validate()?;
        self.minimized.validate()?;
        if self.original.result.verdict != Atv2DifferentialVerdict::Counterexample
            || self.minimized.result.verdict != Atv2DifferentialVerdict::Counterexample
        {
            return Err(Atv2CounterexampleError::OriginalNotCounterexample);
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
            return Err(Atv2CounterexampleError::ArtifactContract);
        }
        let mut current = self.original.input.input_sha256.as_str();
        for (index, attempt) in self.attempts.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| Atv2CounterexampleError::Arithmetic)?;
            if attempt.ordinal != ordinal
                || attempt.before_input_sha256 != current
                || !is_sha256(&attempt.candidate_input_sha256)
                || attempt.candidate_input_sha256 == attempt.before_input_sha256
            {
                return Err(Atv2CounterexampleError::ArtifactContract);
            }
            if attempt.outcome == Atv2ShrinkOutcome::Preserved {
                current = &attempt.candidate_input_sha256;
            }
        }
        if current != self.minimized.input.input_sha256 {
            return Err(Atv2CounterexampleError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, Atv2CounterexampleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| Atv2CounterexampleError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, Atv2CounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn shrink_atv2_counterexample<F, E>(
    matrix_digest_sha256: String,
    original_input: Atv2CounterexampleInput,
    observed: Atv2MatrixCaseArtifact,
    mut evaluator: F,
) -> Result<Atv2CounterexampleBundle, Atv2CounterexampleError>
where
    F: FnMut(&Atv2CounterexampleInput) -> Result<Atv2MatrixCaseArtifact, E>,
    E: Display,
{
    if !is_sha256(&matrix_digest_sha256) {
        return Err(Atv2CounterexampleError::InvalidSha256);
    }
    validate_case_result(&observed)?;
    if observed.verdict != Atv2DifferentialVerdict::Counterexample {
        return Err(Atv2CounterexampleError::OriginalNotCounterexample);
    }
    let reproduced = evaluator(&original_input)
        .map_err(|error| Atv2CounterexampleError::Evaluation(error.to_string()))?;
    validate_case_result(&reproduced)?;
    if reproduced != observed {
        return Err(Atv2CounterexampleError::OriginalReproductionMismatch);
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
            Atv2ShrinkOperation::RemoveCommand {
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
                Atv2ShrinkOperation::ZeroPayloadTag {
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
                Atv2ShrinkOperation::ZeroFault {
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
                Atv2ShrinkOperation::ZeroServiceAlias {
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
                Atv2ShrinkOperation::ZeroPublicSlot {
                    index: index_u32(index)?,
                },
                &difference_signature,
                &mut evaluator,
                &mut state,
                &mut attempts,
            )?;
        }
    }

    let bundle = Atv2CounterexampleBundle {
        schema_version: ATV2_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        shrinker_version: ATV2_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        matrix_digest_sha256,
        hardware_status: HARDWARE_STATUS.to_owned(),
        shrink_order: shrink_order(),
        difference_signature,
        original_first_difference,
        minimized_first_difference: state.first_difference,
        original: Atv2CounterexampleCaseArtifact::new(&original_input, observed)?,
        minimized: Atv2CounterexampleCaseArtifact::new(&state.input, state.result)?,
        attempts,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn verify_atv2_counterexample_bundle_with<F, E>(
    bundle: &Atv2CounterexampleBundle,
    matrix_digest_sha256: String,
    original_input: Atv2CounterexampleInput,
    observed: Atv2MatrixCaseArtifact,
    evaluator: F,
) -> Result<(), Atv2CounterexampleError>
where
    F: FnMut(&Atv2CounterexampleInput) -> Result<Atv2MatrixCaseArtifact, E>,
    E: Display,
{
    bundle.validate()?;
    let recomputed =
        shrink_atv2_counterexample(matrix_digest_sha256, original_input, observed, evaluator)?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(Atv2CounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

pub fn build_atv2_counterexample_bundle(
    compiled: &Atv2CompiledQsm,
    matrix: &Atv2AdversarialMatrix,
    execution: &Atv2MatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: Atv2MatrixLimits,
    engine_digests: &Atv2EngineDigests,
) -> Result<Atv2CounterexampleBundle, Atv2CounterexampleError> {
    matrix
        .validate_against(compiled, matrix_limits)
        .map_err(|error| Atv2CounterexampleError::Matrix(error.to_string()))?;
    execution
        .validate()
        .map_err(|error| Atv2CounterexampleError::MatrixExecution(error.to_string()))?;
    let matrix_digest_sha256 = matrix.matrix_digest().to_hex();
    let matrix_bytes = matrix
        .canonical_bytes()
        .map_err(|error| Atv2CounterexampleError::Matrix(error.to_string()))?;
    if execution.matrix_digest_sha256 != matrix_digest_sha256
        || execution.matrix_bytes_sha256 != sha256_hex(&matrix_bytes)
    {
        return Err(Atv2CounterexampleError::MatrixBinding);
    }
    let original_case = matrix
        .cases()
        .iter()
        .find(|case| case.case_id().to_hex() == original_case_id_sha256)
        .ok_or(Atv2CounterexampleError::CaseNotFound)?;
    let observed = execution
        .cases
        .iter()
        .find(|case| case.case_id_sha256 == original_case_id_sha256)
        .cloned()
        .ok_or(Atv2CounterexampleError::CaseResultNotFound)?;
    let original_input = Atv2CounterexampleInput::from_case(original_case)?;
    shrink_atv2_counterexample(
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

pub fn verify_atv2_counterexample_bundle(
    bundle: &Atv2CounterexampleBundle,
    compiled: &Atv2CompiledQsm,
    matrix: &Atv2AdversarialMatrix,
    execution: &Atv2MatrixExecutionArtifact,
    original_case_id_sha256: &str,
    matrix_limits: Atv2MatrixLimits,
    engine_digests: &Atv2EngineDigests,
) -> Result<(), Atv2CounterexampleError> {
    bundle.validate()?;
    let recomputed = build_atv2_counterexample_bundle(
        compiled,
        matrix,
        execution,
        original_case_id_sha256,
        matrix_limits,
        engine_digests,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(Atv2CounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

struct ShrinkState {
    input: Atv2CounterexampleInput,
    result: Atv2MatrixCaseArtifact,
    first_difference: ComparisonPoint,
}

fn try_candidate<F, E>(
    candidate: Atv2CounterexampleInput,
    operation: Atv2ShrinkOperation,
    expected_signature: &Atv2DifferenceSignature,
    evaluator: &mut F,
    state: &mut ShrinkState,
    attempts: &mut Vec<Atv2ShrinkAttempt>,
) -> Result<(), Atv2CounterexampleError>
where
    F: FnMut(&Atv2CounterexampleInput) -> Result<Atv2MatrixCaseArtifact, E>,
    E: Display,
{
    let before_input_sha256 = state.input.input_sha256()?;
    let candidate_input_sha256 = candidate.input_sha256()?;
    let mut accepted = None;
    let outcome = match evaluator(&candidate) {
        Err(_) => Atv2ShrinkOutcome::EvaluationError,
        Ok(result) if validate_case_result(&result).is_err() => Atv2ShrinkOutcome::EvaluationError,
        Ok(result) if result.verdict != Atv2DifferentialVerdict::Counterexample => {
            Atv2ShrinkOutcome::NotCounterexample
        }
        Ok(result) => match first_typed_difference(&result.differential) {
            Ok((signature, point)) if signature == *expected_signature => {
                accepted = Some((result, point));
                Atv2ShrinkOutcome::Preserved
            }
            Ok(_) => Atv2ShrinkOutcome::DifferentTypedDifference,
            Err(_) => Atv2ShrinkOutcome::EvaluationError,
        },
    };
    attempts.push(Atv2ShrinkAttempt {
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
    compiled: &Atv2CompiledQsm,
    seed: crate::Atv2MatrixSeed,
    input: &Atv2CounterexampleInput,
    matrix_limits: Atv2MatrixLimits,
    engine_digests: &Atv2EngineDigests,
) -> Result<Atv2MatrixCaseArtifact, String> {
    let candidate_matrix =
        Atv2AdversarialMatrix::new(compiled, seed, vec![input.to_case_spec()], matrix_limits)
            .map_err(|error| error.to_string())?;
    let execution = evaluate_atv2_adversarial_matrix(
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
    artifact: &Atv2DifferentialArtifact,
) -> Result<(Atv2DifferenceSignature, ComparisonPoint), Atv2CounterexampleError> {
    artifact
        .validate()
        .map_err(|error| Atv2CounterexampleError::Differential(error.to_string()))?;
    if artifact.source_refinement.verdict == Atv2DifferentialVerdict::Counterexample {
        let point = artifact
            .source_refinement
            .first_difference
            .clone()
            .ok_or(Atv2CounterexampleError::MissingFirstDifference)?;
        return Ok((
            Atv2DifferenceSignature {
                origin: Atv2DifferenceOrigin::SourceRefinement,
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
            .ok_or(Atv2CounterexampleError::MissingFirstDifference)?;
        return Ok((
            Atv2DifferenceSignature {
                origin: Atv2DifferenceOrigin::DifferentialOracle {
                    counterexample_kind: counterexample.kind,
                    left_participant: counterexample.left_participant.clone(),
                    right_participant: counterexample.right_participant.clone(),
                },
                comparison: comparison_signature(&counterexample.first_difference),
            },
            counterexample.first_difference.clone(),
        ));
    }
    Err(Atv2CounterexampleError::MissingFirstDifference)
}

fn comparison_signature(point: &ComparisonPoint) -> Atv2ComparisonSignature {
    match point {
        ComparisonPoint::Trace {
            left_axis,
            right_axis,
            ..
        } => Atv2ComparisonSignature::Trace {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
        ComparisonPoint::Termination {
            left_axis,
            right_axis,
            ..
        } => Atv2ComparisonSignature::Termination {
            left_axis: *left_axis,
            right_axis: *right_axis,
        },
    }
}

fn validate_case_result(result: &Atv2MatrixCaseArtifact) -> Result<(), Atv2CounterexampleError> {
    if !is_sha256(&result.case_id_sha256)
        || result.scenario_axis.is_empty()
        || result.host_axis.is_empty()
        || result.resource_axis.is_empty()
    {
        return Err(Atv2CounterexampleError::ArtifactContract);
    }
    result
        .differential
        .validate()
        .map_err(|error| Atv2CounterexampleError::Differential(error.to_string()))?;
    let expected = if result.injection == Atv2HostInjection::NotApplicable {
        Atv2DifferentialVerdict::Unresolved
    } else {
        result.differential.verdict
    };
    if result.verdict != expected {
        return Err(Atv2CounterexampleError::ArtifactContract);
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
) -> Result<(), Atv2CounterexampleError> {
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
        return Err(Atv2CounterexampleError::InputContract);
    }
    Ok(())
}

#[derive(Serialize)]
struct InputBody<'a> {
    schema_version: &'static str,
    scenario_axis: &'a str,
    host_axis: &'a str,
    resource_axis: &'a str,
    commands: &'a [Atv2CommandArtifact],
    limits: &'a Atv2LimitsArtifact,
}

fn input_sha256(
    scenario_axis: &str,
    host_axis: &str,
    resource_axis: &str,
    commands: &[Atv2CommandArtifact],
    limits: &Atv2LimitsArtifact,
) -> Result<String, Atv2CounterexampleError> {
    let bytes = serde_json::to_vec(&InputBody {
        schema_version: ATV2_COUNTEREXAMPLE_BUNDLE_VERSION,
        scenario_axis,
        host_axis,
        resource_axis,
        commands,
        limits,
    })
    .map_err(|error| Atv2CounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn case_result_sha256(result: &Atv2MatrixCaseArtifact) -> Result<String, Atv2CounterexampleError> {
    validate_case_result(result)?;
    let bytes = serde_json::to_vec(result)
        .map_err(|error| Atv2CounterexampleError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn shrink_order() -> Vec<String> {
    SHRINK_ORDER.iter().map(|step| (*step).to_owned()).collect()
}

fn index_u32(index: usize) -> Result<u32, Atv2CounterexampleError> {
    u32::try_from(index).map_err(|_| Atv2CounterexampleError::Arithmetic)
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

fn scenario_name(value: Atv2ScenarioAxis) -> &'static str {
    match value {
        Atv2ScenarioAxis::Normal => "NORMAL",
        Atv2ScenarioAxis::Reset => "RESET",
        Atv2ScenarioAxis::Handoff => "HANDOFF",
        Atv2ScenarioAxis::DeadlineBefore => "DEADLINE_BEFORE",
        Atv2ScenarioAxis::DeadlineAt => "DEADLINE_AT",
        Atv2ScenarioAxis::DeadlineAfter => "DEADLINE_AFTER",
        Atv2ScenarioAxis::UnknownService => "UNKNOWN_SERVICE",
        Atv2ScenarioAxis::PublicFaultTimeout => "PUBLIC_FAULT_TIMEOUT",
        Atv2ScenarioAxis::PublicFaultReconnect => "PUBLIC_FAULT_RECONNECT",
        Atv2ScenarioAxis::PublicFaultLoss => "PUBLIC_FAULT_LOSS",
    }
}

fn host_name(value: Atv2HostAxis) -> &'static str {
    match value {
        Atv2HostAxis::Continue => "CONTINUE",
        Atv2HostAxis::Terminate => "TERMINATE",
        Atv2HostAxis::Timeout => "TIMEOUT",
        Atv2HostAxis::Reconnect => "RECONNECT",
        Atv2HostAxis::Loss => "LOSS",
    }
}

fn resource_name(value: Atv2ResourceAxis) -> &'static str {
    match value {
        Atv2ResourceAxis::Nominal => "NOMINAL",
        Atv2ResourceAxis::FuelBoundary => "FUEL_BOUNDARY",
        Atv2ResourceAxis::MemoryBoundary => "MEMORY_BOUNDARY",
        Atv2ResourceAxis::HostCallBoundary => "HOST_CALL_BOUNDARY",
    }
}

#[derive(Debug, Error)]
pub enum Atv2CounterexampleError {
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
