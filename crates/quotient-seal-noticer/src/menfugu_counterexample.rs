use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, DifferentialOracle, DifferentialVerdict, ExecutionLimits,
    ExecutionTermination, HostOutcomeRecord, ObservableAxis, ObservableEvent, ScalarValue,
    TrapClass,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    build_menfugu_injected_fixture_artifact, evaluate_menfugu_differential, MenfuguAdversarialCase,
    MenfuguAdversarialMatrix, MenfuguCompiledQsm, MenfuguDifferentialArtifact,
    MenfuguDifferentialEvidenceOrigin, MenfuguDifferentialVerdict, MenfuguEngineDigests,
    MenfuguProfileAxis, MenfuguPublicInput, MenfuguPublicSequence, MenfuguScenarioAxis,
};

pub const MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION: &str = "noticer-menfugu-counterexample-bundle/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const EVIDENCE_ORIGIN: &str = "INJECTED_TEST_FIXTURE";
const MAX_COMMANDS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum MenfuguInjection {
    TargetOnlyAction {
        engine_index: u8,
        action: u32,
        slot: u64,
    },
    ExtraHostCall {
        engine_index: u8,
        action: u32,
        slot: u32,
    },
    TargetOnlyTrap {
        engine_index: u8,
    },
}

impl MenfuguInjection {
    const fn engine_index(self) -> usize {
        match self {
            Self::TargetOnlyAction { engine_index, .. }
            | Self::ExtraHostCall { engine_index, .. }
            | Self::TargetOnlyTrap { engine_index } => engine_index as usize,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::TargetOnlyAction { .. } => "TARGET_ONLY_ACTION_TEST_INSTRUMENTATION",
            Self::ExtraHostCall { .. } => "EXTRA_HOST_CALL_TEST_INSTRUMENTATION",
            Self::TargetOnlyTrap { .. } => "TARGET_ONLY_TRAP_TEST_INSTRUMENTATION",
        }
    }

    const fn origin(self) -> MenfuguDifferenceOrigin {
        match self {
            Self::TargetOnlyAction { .. } => MenfuguDifferenceOrigin::TargetOnlyAction,
            Self::ExtraHostCall { .. } => MenfuguDifferenceOrigin::ExtraHostCall,
            Self::TargetOnlyTrap { .. } => MenfuguDifferenceOrigin::TargetOnlyTrap,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguDifferenceOrigin {
    TargetOnlyAction,
    ExtraHostCall,
    TargetOnlyTrap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguDifferenceSignature {
    pub origin: MenfuguDifferenceOrigin,
    pub engine_name: String,
    pub first_difference: ComparisonPoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguCommandArtifact {
    pub family: String,
    pub service_alias: u32,
    pub public_slot: u64,
    pub input: u8,
    pub payload_tag: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguLimitsArtifact {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

impl From<ExecutionLimits> for MenfuguLimitsArtifact {
    fn from(value: ExecutionLimits) -> Self {
        Self {
            fuel: value.fuel,
            max_memory_pages: value.max_memory_pages,
            max_host_calls: value.max_host_calls,
            timeout_ms: value.timeout_ms,
        }
    }
}

impl From<MenfuguLimitsArtifact> for ExecutionLimits {
    fn from(value: MenfuguLimitsArtifact) -> Self {
        Self {
            fuel: value.fuel,
            max_memory_pages: value.max_memory_pages,
            max_host_calls: value.max_host_calls,
            timeout_ms: value.timeout_ms,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguCounterexampleInputArtifact {
    pub case_id_sha256: String,
    pub profile_axis: String,
    pub scenario_axis: String,
    pub commands: Vec<MenfuguCommandArtifact>,
    pub limits: MenfuguLimitsArtifact,
    pub injection: MenfuguInjection,
}

impl MenfuguCounterexampleInputArtifact {
    pub fn canonical_json(&self) -> Result<Vec<u8>, MenfuguCounterexampleError> {
        validate_input_shape(self)?;
        serde_json::to_vec(self)
            .map_err(|error| MenfuguCounterexampleError::Serialization(error.to_string()))
    }

    pub fn input_sha256(&self) -> Result<String, MenfuguCounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguCounterexampleCaseArtifact {
    pub input: MenfuguCounterexampleInputArtifact,
    pub input_sha256: String,
    pub result_sha256: String,
    pub verdict: MenfuguDifferentialVerdict,
    pub difference: MenfuguDifferenceSignature,
    pub differential: MenfuguDifferentialArtifact,
}

impl MenfuguCounterexampleCaseArtifact {
    pub fn validate(&self) -> Result<(), MenfuguCounterexampleError> {
        let computed_result_sha256 = sha256_hex(
            &self
                .differential
                .canonical_json()
                .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?,
        );
        if self.input.input_sha256()? != self.input_sha256
            || !is_sha256(&self.result_sha256)
            || self.verdict != MenfuguDifferentialVerdict::Counterexample
            || self.differential.verdict != self.verdict
            || self.differential.evidence_origin
                != MenfuguDifferentialEvidenceOrigin::InjectedTestFixture
            || self.differential.injection_label.as_deref() != Some(self.input.injection.label())
            || computed_result_sha256 != self.result_sha256
            || derive_difference(self.input.injection, &self.differential)? != self.difference
        {
            return Err(MenfuguCounterexampleError::ArtifactContract);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguShrinkOperation {
    RemoveTrailingStop,
    RemovePrimaryStimulus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MenfuguShrinkOutcome {
    AcceptedSameTypedDifference,
    RejectedDifferentDifference,
    RejectedUnresolved,
    RejectedEvaluationError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguShrinkAttempt {
    pub order: u32,
    pub operation: MenfuguShrinkOperation,
    pub candidate_input_sha256: Option<String>,
    pub outcome: MenfuguShrinkOutcome,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MenfuguCounterexampleBundle {
    pub schema_version: String,
    pub evaluator_version: String,
    pub matrix_digest_sha256: String,
    pub case_id_sha256: String,
    pub source_digest_sha256: String,
    pub transition_digest_sha256: String,
    pub module_digest_sha256: String,
    pub capsule_digest_sha256: String,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub original: MenfuguCounterexampleCaseArtifact,
    pub minimized: MenfuguCounterexampleCaseArtifact,
    pub first_typed_difference: MenfuguDifferenceSignature,
    pub shrink_attempts: Vec<MenfuguShrinkAttempt>,
}

impl MenfuguCounterexampleBundle {
    pub fn validate(&self) -> Result<(), MenfuguCounterexampleError> {
        if self.schema_version != MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.evaluator_version != MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION
            || self.evidence_origin != EVIDENCE_ORIGIN
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.matrix_digest_sha256)
            || !is_sha256(&self.case_id_sha256)
            || !is_sha256(&self.source_digest_sha256)
            || !is_sha256(&self.transition_digest_sha256)
            || !is_sha256(&self.module_digest_sha256)
            || !is_sha256(&self.capsule_digest_sha256)
            || self.original.input.case_id_sha256 != self.case_id_sha256
            || self.minimized.input.case_id_sha256 != self.case_id_sha256
            || self.original.input.injection.origin() != self.first_typed_difference.origin
            || self.minimized.input.injection.origin() != self.first_typed_difference.origin
            || self.minimized.difference != self.first_typed_difference
            || self.shrink_attempts.len() != 2
            || self.shrink_attempts[0].order != 0
            || self.shrink_attempts[0].operation != MenfuguShrinkOperation::RemoveTrailingStop
            || self.shrink_attempts[1].order != 1
            || self.shrink_attempts[1].operation != MenfuguShrinkOperation::RemovePrimaryStimulus
        {
            return Err(MenfuguCounterexampleError::ArtifactContract);
        }
        self.original.validate()?;
        self.minimized.validate()?;
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, MenfuguCounterexampleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| MenfuguCounterexampleError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, MenfuguCounterexampleError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn build_menfugu_counterexample_bundle(
    compiled: &MenfuguCompiledQsm,
    matrix: &MenfuguAdversarialMatrix,
    case_id_sha256: &str,
    injection: MenfuguInjection,
    engine_digests: &MenfuguEngineDigests,
) -> Result<MenfuguCounterexampleBundle, MenfuguCounterexampleError> {
    matrix
        .validate_against(compiled, crate::MenfuguAdversarialMatrixLimits::default())
        .map_err(|error| MenfuguCounterexampleError::Matrix(error.to_string()))?;
    let case = matrix
        .cases()
        .iter()
        .find(|case| hex(case.case_id().as_bytes()) == case_id_sha256)
        .ok_or(MenfuguCounterexampleError::CaseNotFound)?;
    ensure_supported_case(case)?;
    let original_input = input_from_case(case, injection)?;
    let original = evaluate_input(compiled, original_input.clone(), engine_digests)?;
    let (minimized, shrink_attempts) = shrink_input(
        compiled,
        original_input,
        &original.difference,
        engine_digests,
    )?;
    let binding = compiled.binding();
    let bundle = MenfuguCounterexampleBundle {
        schema_version: MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        evaluator_version: MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION.to_owned(),
        matrix_digest_sha256: hex(matrix.matrix_digest().as_bytes()),
        case_id_sha256: case_id_sha256.to_owned(),
        source_digest_sha256: hex(binding.source_digest.as_bytes()),
        transition_digest_sha256: hex(binding.transition_digest.as_bytes()),
        module_digest_sha256: hex(binding.module_digest.as_bytes()),
        capsule_digest_sha256: hex(binding.capsule_digest.as_bytes()),
        evidence_origin: EVIDENCE_ORIGIN.to_owned(),
        hardware_status: HARDWARE_STATUS.to_owned(),
        original,
        first_typed_difference: minimized.difference.clone(),
        minimized,
        shrink_attempts,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn verify_menfugu_counterexample_bundle(
    bundle: &MenfuguCounterexampleBundle,
    compiled: &MenfuguCompiledQsm,
    matrix: &MenfuguAdversarialMatrix,
    engine_digests: &MenfuguEngineDigests,
) -> Result<(), MenfuguCounterexampleError> {
    bundle.validate()?;
    let recomputed = build_menfugu_counterexample_bundle(
        compiled,
        matrix,
        &bundle.case_id_sha256,
        bundle.original.input.injection,
        engine_digests,
    )?;
    if &recomputed != bundle || recomputed.canonical_json()? != bundle.canonical_json()? {
        return Err(MenfuguCounterexampleError::RecomputationMismatch);
    }
    Ok(())
}

fn ensure_supported_case(case: &MenfuguAdversarialCase) -> Result<(), MenfuguCounterexampleError> {
    if case.profile() != MenfuguProfileAxis::P0PublicQuotientOnly
        || case.scenario() != MenfuguScenarioAxis::Cover
    {
        return Err(MenfuguCounterexampleError::UnsupportedCase);
    }
    Ok(())
}

fn input_from_case(
    case: &MenfuguAdversarialCase,
    injection: MenfuguInjection,
) -> Result<MenfuguCounterexampleInputArtifact, MenfuguCounterexampleError> {
    if injection.engine_index() >= 2 {
        return Err(MenfuguCounterexampleError::InjectionTarget);
    }
    let commands = case
        .sequence()
        .commands()
        .iter()
        .map(command_to_artifact)
        .collect::<Result<Vec<_>, _>>()?;
    let input = MenfuguCounterexampleInputArtifact {
        case_id_sha256: hex(case.case_id().as_bytes()),
        profile_axis: case.profile().name().to_owned(),
        scenario_axis: case.scenario().name().to_owned(),
        commands,
        limits: case.sequence().limits().into(),
        injection,
    };
    validate_input_shape(&input)?;
    Ok(input)
}

fn command_to_artifact(
    command: &ContextCommand,
) -> Result<MenfuguCommandArtifact, MenfuguCounterexampleError> {
    let family = if command.family == ContextFamily::Tick {
        "TICK"
    } else if command.family == ContextFamily::Stop {
        "STOP"
    } else {
        return Err(MenfuguCounterexampleError::UnsupportedCase);
    };
    Ok(MenfuguCommandArtifact {
        family: family.to_owned(),
        service_alias: command.service_alias,
        public_slot: command.public_slot,
        input: command.fault,
        payload_tag: command.payload_tag,
    })
}

fn artifact_to_commands(
    input: &MenfuguCounterexampleInputArtifact,
) -> Result<Vec<ContextCommand>, MenfuguCounterexampleError> {
    validate_input_shape(input)?;
    input
        .commands
        .iter()
        .map(|command| {
            let family = match command.family.as_str() {
                "TICK" => ContextFamily::Tick,
                "STOP" => ContextFamily::Stop,
                _ => return Err(MenfuguCounterexampleError::InputContract),
            };
            Ok(ContextCommand {
                family,
                kind: family.command_kind(),
                service_alias: command.service_alias,
                public_slot: command.public_slot,
                fault: command.input,
                payload_tag: command.payload_tag,
            })
        })
        .collect()
}

fn validate_input_shape(
    input: &MenfuguCounterexampleInputArtifact,
) -> Result<(), MenfuguCounterexampleError> {
    if !is_sha256(&input.case_id_sha256)
        || input.profile_axis != MenfuguProfileAxis::P0PublicQuotientOnly.name()
        || input.scenario_axis != MenfuguScenarioAxis::Cover.name()
        || input.commands.is_empty()
        || input.commands.len() > 2
        || input.injection.engine_index() >= 2
        || input.limits.fuel == 0
        || input.limits.max_memory_pages == 0
        || input.limits.max_host_calls == 0
        || input.limits.timeout_ms == 0
    {
        return Err(MenfuguCounterexampleError::InputContract);
    }
    let first = &input.commands[0];
    if first.family != "TICK"
        || first.service_alias == 0
        || first.public_slot != 0
        || first.input != MenfuguPublicInput::Cover as u8
        || first.payload_tag != 0
    {
        return Err(MenfuguCounterexampleError::InputContract);
    }
    if let Some(stop) = input.commands.get(1) {
        if stop.family != "STOP"
            || stop.service_alias != 0
            || stop.public_slot != 0
            || stop.input != 0
            || stop.payload_tag != 0
        {
            return Err(MenfuguCounterexampleError::InputContract);
        }
    }
    Ok(())
}

fn evaluate_input(
    compiled: &MenfuguCompiledQsm,
    input: MenfuguCounterexampleInputArtifact,
    engine_digests: &MenfuguEngineDigests,
) -> Result<MenfuguCounterexampleCaseArtifact, MenfuguCounterexampleError> {
    let commands = artifact_to_commands(&input)?;
    let sequence =
        MenfuguPublicSequence::new(compiled, commands, input.limits.into(), MAX_COMMANDS)
            .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?;
    let base = evaluate_menfugu_differential(compiled, &sequence, engine_digests)
        .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?;
    if base.verdict != MenfuguDifferentialVerdict::Match {
        return Err(MenfuguCounterexampleError::BaselineNotMatch);
    }
    let mut engines = base.oracle.engines.clone();
    let engine = engines
        .get_mut(input.injection.engine_index())
        .ok_or(MenfuguCounterexampleError::InjectionTarget)?;
    apply_injection(engine, input.injection)?;
    let oracle = DifferentialOracle::evaluate(base.oracle.reference.clone(), engines)
        .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?;
    if oracle.verdict != DifferentialVerdict::Counterexample {
        return Err(MenfuguCounterexampleError::NoCounterexample);
    }
    let differential =
        build_menfugu_injected_fixture_artifact(&base, oracle, input.injection.label())
            .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?;
    let difference = derive_difference(input.injection, &differential)?;
    let input_sha256 = input.input_sha256()?;
    let result_sha256 = sha256_hex(
        &differential
            .canonical_json()
            .map_err(|error| MenfuguCounterexampleError::Evaluation(error.to_string()))?,
    );
    let artifact = MenfuguCounterexampleCaseArtifact {
        input,
        input_sha256,
        result_sha256,
        verdict: MenfuguDifferentialVerdict::Counterexample,
        difference,
        differential,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn apply_injection(
    engine: &mut quotient_seal_engine::EngineRunArtifact,
    injection: MenfuguInjection,
) -> Result<(), MenfuguCounterexampleError> {
    match injection {
        MenfuguInjection::TargetOnlyAction { action, slot, .. } => {
            let index = engine
                .trace
                .iter()
                .position(|event| matches!(event, ObservableEvent::EmitFrame { .. }))
                .ok_or(MenfuguCounterexampleError::InjectionTarget)?
                + 1;
            engine.trace.insert(
                index,
                ObservableEvent::EmitAction {
                    action,
                    slot,
                    return_code: 0,
                },
            );
        }
        MenfuguInjection::ExtraHostCall { action, slot, .. } => {
            engine.trace.insert(
                1.min(engine.trace.len()),
                ObservableEvent::HostImport {
                    import: "qseal.emit_action".to_owned(),
                    arguments: vec![
                        ScalarValue::I32 { bits: action },
                        ScalarValue::I32 { bits: slot },
                    ],
                    outcome: HostOutcomeRecord::Continue,
                },
            );
        }
        MenfuguInjection::TargetOnlyTrap { .. } => {
            let detail = "MENFUGU_TARGET_ONLY_INJECTED_TRAP";
            engine.termination = ExecutionTermination::Trapped {
                class: TrapClass::Unreachable,
                engine_code: detail.to_owned(),
                detail_sha256: sha256_hex(detail.as_bytes()),
            };
        }
    }
    Ok(())
}

fn derive_difference(
    injection: MenfuguInjection,
    differential: &MenfuguDifferentialArtifact,
) -> Result<MenfuguDifferenceSignature, MenfuguCounterexampleError> {
    let counterexample = differential
        .oracle
        .counterexamples
        .first()
        .ok_or(MenfuguCounterexampleError::NoCounterexample)?;
    let engine = differential
        .oracle
        .engines
        .get(injection.engine_index())
        .ok_or(MenfuguCounterexampleError::InjectionTarget)?;
    let signature = MenfuguDifferenceSignature {
        origin: injection.origin(),
        engine_name: engine.input.engine.name.clone(),
        first_difference: counterexample.first_difference.clone(),
    };
    if !difference_matches_origin(&signature) {
        return Err(MenfuguCounterexampleError::DifferentDifference);
    }
    Ok(signature)
}

fn difference_matches_origin(signature: &MenfuguDifferenceSignature) -> bool {
    matches!(
        (&signature.origin, &signature.first_difference),
        (
            MenfuguDifferenceOrigin::TargetOnlyAction,
            ComparisonPoint::Trace {
                right_axis: Some(ObservableAxis::Output),
                ..
            },
        )
        | (
            MenfuguDifferenceOrigin::ExtraHostCall,
            ComparisonPoint::Trace {
                right_axis: Some(ObservableAxis::HostImport),
                ..
            },
        )
        | (
            MenfuguDifferenceOrigin::TargetOnlyTrap,
            ComparisonPoint::Termination {
                right_axis: ObservableAxis::Trap,
                ..
            },
        )
    )
}

fn same_typed_difference(
    expected: &MenfuguDifferenceSignature,
    actual: &MenfuguDifferenceSignature,
) -> bool {
    if expected.origin != actual.origin || expected.engine_name != actual.engine_name {
        return false;
    }
    match (&expected.first_difference, &actual.first_difference) {
        (
            ComparisonPoint::Trace {
                left_axis: expected_left,
                right_axis: expected_right,
                ..
            },
            ComparisonPoint::Trace {
                left_axis: actual_left,
                right_axis: actual_right,
                ..
            },
        ) => expected_left == actual_left && expected_right == actual_right,
        (
            ComparisonPoint::Termination {
                left_axis: expected_left,
                right_axis: expected_right,
                ..
            },
            ComparisonPoint::Termination {
                left_axis: actual_left,
                right_axis: actual_right,
                ..
            },
        ) => expected_left == actual_left && expected_right == actual_right,
        _ => false,
    }
}

fn shrink_input(
    compiled: &MenfuguCompiledQsm,
    original: MenfuguCounterexampleInputArtifact,
    expected: &MenfuguDifferenceSignature,
    engine_digests: &MenfuguEngineDigests,
) -> Result<
    (MenfuguCounterexampleCaseArtifact, Vec<MenfuguShrinkAttempt>),
    MenfuguCounterexampleError,
> {
    let mut current_input = original;
    let mut current = evaluate_input(compiled, current_input.clone(), engine_digests)?;
    let mut attempts = Vec::with_capacity(2);

    let mut remove_stop = current_input.clone();
    if remove_stop
        .commands
        .last()
        .is_some_and(|command| command.family == "STOP")
    {
        remove_stop.commands.pop();
    }
    let stop_hash = remove_stop.input_sha256().ok();
    match evaluate_input(compiled, remove_stop.clone(), engine_digests) {
        Ok(candidate) if same_typed_difference(expected, &candidate.difference) => {
            attempts.push(MenfuguShrinkAttempt {
                order: 0,
                operation: MenfuguShrinkOperation::RemoveTrailingStop,
                candidate_input_sha256: stop_hash,
                outcome: MenfuguShrinkOutcome::AcceptedSameTypedDifference,
                detail: "SAME_TYPED_DIFFERENCE".to_owned(),
            });
            current_input = remove_stop;
            current = candidate;
        }
        Ok(_) => attempts.push(MenfuguShrinkAttempt {
            order: 0,
            operation: MenfuguShrinkOperation::RemoveTrailingStop,
            candidate_input_sha256: stop_hash,
            outcome: MenfuguShrinkOutcome::RejectedDifferentDifference,
            detail: "DIFFERENCE_SIGNATURE_CHANGED".to_owned(),
        }),
        Err(MenfuguCounterexampleError::BaselineNotMatch) => {
            attempts.push(MenfuguShrinkAttempt {
                order: 0,
                operation: MenfuguShrinkOperation::RemoveTrailingStop,
                candidate_input_sha256: stop_hash,
                outcome: MenfuguShrinkOutcome::RejectedUnresolved,
                detail: "BASELINE_NOT_MATCH".to_owned(),
            });
        }
        Err(error) => attempts.push(MenfuguShrinkAttempt {
            order: 0,
            operation: MenfuguShrinkOperation::RemoveTrailingStop,
            candidate_input_sha256: stop_hash,
            outcome: MenfuguShrinkOutcome::RejectedEvaluationError,
            detail: format!("EVALUATION_ERROR:{error}"),
        }),
    }

    let mut remove_stimulus = current_input.clone();
    if !remove_stimulus.commands.is_empty() {
        remove_stimulus.commands.remove(0);
    }
    let stimulus_hash = serde_json::to_vec(&remove_stimulus)
        .ok()
        .map(|bytes| sha256_hex(&bytes));
    match evaluate_input(compiled, remove_stimulus, engine_digests) {
        Ok(candidate) if same_typed_difference(expected, &candidate.difference) => {
            attempts.push(MenfuguShrinkAttempt {
                order: 1,
                operation: MenfuguShrinkOperation::RemovePrimaryStimulus,
                candidate_input_sha256: stimulus_hash,
                outcome: MenfuguShrinkOutcome::AcceptedSameTypedDifference,
                detail: "SAME_TYPED_DIFFERENCE".to_owned(),
            });
            current = candidate;
        }
        Ok(_) => attempts.push(MenfuguShrinkAttempt {
            order: 1,
            operation: MenfuguShrinkOperation::RemovePrimaryStimulus,
            candidate_input_sha256: stimulus_hash,
            outcome: MenfuguShrinkOutcome::RejectedDifferentDifference,
            detail: "DIFFERENCE_SIGNATURE_CHANGED".to_owned(),
        }),
        Err(MenfuguCounterexampleError::BaselineNotMatch) => {
            attempts.push(MenfuguShrinkAttempt {
                order: 1,
                operation: MenfuguShrinkOperation::RemovePrimaryStimulus,
                candidate_input_sha256: stimulus_hash,
                outcome: MenfuguShrinkOutcome::RejectedUnresolved,
                detail: "BASELINE_NOT_MATCH".to_owned(),
            });
        }
        Err(error) => attempts.push(MenfuguShrinkAttempt {
            order: 1,
            operation: MenfuguShrinkOperation::RemovePrimaryStimulus,
            candidate_input_sha256: stimulus_hash,
            outcome: MenfuguShrinkOutcome::RejectedEvaluationError,
            detail: format!("EVALUATION_ERROR:{error}"),
        }),
    }
    Ok((current, attempts))
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
pub enum MenfuguCounterexampleError {
    #[error("matrix validation failed: {0}")]
    Matrix(String),
    #[error("counterexample source case was not found")]
    CaseNotFound,
    #[error("counterexample source case must be P0 COVER")]
    UnsupportedCase,
    #[error("injection target engine or trace point is invalid")]
    InjectionTarget,
    #[error("counterexample input violated its contract")]
    InputContract,
    #[error("counterexample evaluation failed: {0}")]
    Evaluation(String),
    #[error("baseline execution was not MATCH")]
    BaselineNotMatch,
    #[error("injection did not produce a counterexample")]
    NoCounterexample,
    #[error("first typed difference did not match the requested injection")]
    DifferentDifference,
    #[error("counterexample artifact violated its contract")]
    ArtifactContract,
    #[error("counterexample artifact serialization failed: {0}")]
    Serialization(String),
    #[error("counterexample full recomputation mismatch")]
    RecomputationMismatch,
}
