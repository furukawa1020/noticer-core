use std::collections::{BTreeMap, BTreeSet};

use quotient_forge_caqt::{artifact_digest, Digest};
use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, ContextCommandRecord, DifferentialOracle, DifferentialOracleArtifact,
    DifferentialVerdict, EngineIdentity, EngineRunArtifact, EngineRunVerdict, ExecutionInput,
    ExecutionLimits, ExecutionTermination, HostOutcomeRecord, HostTapeRecord, ObservableAxis,
    ObservableEvent, ResourceKind, ScalarValue, TrapClass, WasmiAdapter, WasmtimeAdapter,
    ENGINE_ADAPTER_CONTRACT_VERSION, REFERENCE_ENGINE_NAME,
};
use quotient_seal_small_step::{
    CheckerMemoryPatch, CheckerSeed, ExecutionEvent, HostDirective, HostOutcome, InterpreterLimits,
    MachineStatus, PublicHostFault, PublicHostTape, ResourceExhaustion, TrapCode, Value,
    WasmMachine, QUOTIENT_SEAL_SMALL_STEP_V1,
};
use quotient_seal_target_ir::{parse_and_lower, CanonicalTargetIr, ParserLimits};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    aepa_transition_digest, AepaCompiledQsm, AepaLoweredTransition, AepaPublicInput,
    AepaPublicOutput, AepaPublicState, AEPA_OUT_OF_ORDER_PUBLIC_STEP, AEPA_PUBLIC_FAULT,
    AEPA_PUBLIC_REJECT, AEPA_UNKNOWN_PUBLIC_INPUT, AEPA_UNKNOWN_PUBLIC_SERVICE,
};

pub const AEPA_DIFFERENTIAL_VERSION: &str = "noticer-aepa-differential/v1";
const SMALL_STEP_ADAPTER_VERSION: &str = "noticer-aepa-small-step-adapter/v1";
const SOURCE_REFERENCE_VERSION: &str = "noticer-aepa-source-reference/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";
const SEQUENCE_MAGIC: &[u8; 8] = b"AEPSEQ01";
const SEQUENCE_DIGEST_DOMAIN: &[u8] = b"noticer-aepa-public-sequence-v1";
const REFERENCE_EXECUTABLE_DOMAIN: &[u8] = b"noticer-aepa-source-reference-code-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaEngineDigests {
    small_step_sha256: String,
    wasmi_sha256: String,
    wasmtime_sha256: String,
}

impl AepaEngineDigests {
    pub fn new(
        small_step_sha256: impl Into<String>,
        wasmi_sha256: impl Into<String>,
        wasmtime_sha256: impl Into<String>,
    ) -> Result<Self, AepaDifferentialError> {
        let digests = Self {
            small_step_sha256: small_step_sha256.into(),
            wasmi_sha256: wasmi_sha256.into(),
            wasmtime_sha256: wasmtime_sha256.into(),
        };
        for (engine, digest) in [
            (REFERENCE_ENGINE_NAME, digests.small_step_sha256.as_str()),
            ("wasmi", digests.wasmi_sha256.as_str()),
            ("wasmtime", digests.wasmtime_sha256.as_str()),
        ] {
            if !is_sha256(digest) {
                return Err(AepaDifferentialError::InvalidExecutableDigest {
                    engine: engine.to_owned(),
                });
            }
        }
        Ok(digests)
    }

    #[must_use]
    pub fn small_step_sha256(&self) -> &str {
        &self.small_step_sha256
    }

    #[must_use]
    pub fn wasmi_sha256(&self) -> &str {
        &self.wasmi_sha256
    }

    #[must_use]
    pub fn wasmtime_sha256(&self) -> &str {
        &self.wasmtime_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaDifferentialVerdict {
    Match,
    Counterexample,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AepaDifferentialEvidenceOrigin {
    ExecutedSoftware,
    InjectedTestFixture,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaExpectedTransition {
    pub source_state: u8,
    pub public_input: u8,
    pub target_state: u8,
    pub public_output: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaSourceRefinement {
    pub verdict: AepaDifferentialVerdict,
    pub first_difference: Option<ComparisonPoint>,
    pub unresolved_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaPublicSequence {
    commands: Box<[ContextCommand]>,
    host_tape: PublicHostTape,
    limits: ExecutionLimits,
    digest: Digest,
}

impl AepaPublicSequence {
    pub fn new(
        compiled: &AepaCompiledQsm,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
        max_commands: usize,
    ) -> Result<Self, AepaDifferentialError> {
        if commands.is_empty() || commands.len() > max_commands || max_commands == 0 {
            return Err(AepaDifferentialError::CommandCount);
        }
        if limits.fuel == 0
            || limits.max_memory_pages == 0
            || limits.max_host_calls == 0
            || limits.timeout_ms == 0
        {
            return Err(AepaDifferentialError::InvalidLimits);
        }
        validate_commands(&commands)?;
        let host_tape = expected_host_tape(compiled, &commands)?;
        let digest = sequence_digest(compiled, &commands, &host_tape, limits)?;
        Ok(Self {
            commands: commands.into_boxed_slice(),
            host_tape,
            limits,
            digest,
        })
    }

    #[must_use]
    pub fn commands(&self) -> &[ContextCommand] {
        &self.commands
    }

    #[must_use]
    pub fn host_tape(&self) -> &PublicHostTape {
        &self.host_tape
    }

    #[must_use]
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AepaDifferentialArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub source_digest_sha256: String,
    pub transition_digest_sha256: String,
    pub sequence_digest_sha256: String,
    pub hardware_status: String,
    pub evidence_origin: AepaDifferentialEvidenceOrigin,
    pub injection_label: Option<String>,
    pub engine_digests: AepaEngineDigests,
    pub source_transitions: Vec<AepaExpectedTransition>,
    pub verdict: AepaDifferentialVerdict,
    pub source_reference: Option<EngineRunArtifact>,
    pub source_refinement: AepaSourceRefinement,
    pub oracle: DifferentialOracleArtifact,
}

impl AepaDifferentialArtifact {
    pub fn validate(&self) -> Result<(), AepaDifferentialError> {
        if self.schema_version != AEPA_DIFFERENTIAL_VERSION
            || self.evaluator_version != AEPA_DIFFERENTIAL_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.source_digest_sha256)
            || !is_sha256(&self.transition_digest_sha256)
            || !is_sha256(&self.sequence_digest_sha256)
            || !source_transitions_are_canonical(
                &self.source_transitions,
                &self.transition_digest_sha256,
            )
            || !engine_digests_match(&self.engine_digests, &self.oracle)
            || !evidence_origin_is_valid(self.evidence_origin, self.injection_label.as_deref())
        {
            return Err(AepaDifferentialError::ArtifactContract);
        }
        self.oracle
            .validate()
            .map_err(|error| AepaDifferentialError::Oracle(error.to_string()))?;
        let expected_refinement = source_refinement(
            self.source_reference.as_ref(),
            &self.oracle.reference,
            self.source_refinement.unresolved_reason.clone(),
        )?;
        if expected_refinement != self.source_refinement
            || aggregate_verdict(expected_refinement.verdict, self.oracle.verdict) != self.verdict
        {
            return Err(AepaDifferentialError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AepaDifferentialError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AepaDifferentialError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AepaDifferentialError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_aepa_differential(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaDifferentialArtifact, AepaDifferentialError> {
    evaluate_aepa_differential_with_host_tape(
        compiled,
        sequence,
        sequence.host_tape(),
        engine_digests,
    )
}

pub fn evaluate_aepa_differential_with_host_tape(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
    host_tape: &PublicHostTape,
    engine_digests: &AepaEngineDigests,
) -> Result<AepaDifferentialArtifact, AepaDifferentialError> {
    validate_host_tape_shape(sequence.host_tape(), host_tape)?;
    let source_verdict = evaluate_source_reference(compiled, sequence)?;
    let (source_reference, source_unresolved) = match source_verdict {
        SourceReferenceVerdict::Executed(artifact) => (
            Some(project_source_reference(artifact.as_ref(), host_tape)?),
            None,
        ),
        SourceReferenceVerdict::Unresolved(reason) => (None, Some(reason)),
    };
    let small_step = execute_small_step(
        compiled,
        sequence,
        host_tape,
        engine_digests.small_step_sha256(),
    )?;
    let wasmi = WasmiAdapter::new(engine_digests.wasmi_sha256())
        .map_err(|error| external_error("wasmi", error))?
        .execute(
            compiled.wasm(),
            host_tape,
            sequence.commands(),
            sequence.limits(),
        )
        .map_err(|error| external_error("wasmi", error))?;
    let wasmtime = WasmtimeAdapter::new(engine_digests.wasmtime_sha256())
        .map_err(|error| external_error("wasmtime", error))?
        .execute(
            compiled.wasm(),
            host_tape,
            sequence.commands(),
            sequence.limits(),
        )
        .map_err(|error| external_error("wasmtime", error))?;
    let oracle = DifferentialOracle::evaluate(small_step, vec![wasmi, wasmtime])
        .map_err(|error| AepaDifferentialError::Oracle(error.to_string()))?;
    let source_refinement = source_refinement(
        source_reference.as_ref(),
        &oracle.reference,
        source_unresolved,
    )?;
    let verdict = aggregate_verdict(source_refinement.verdict, oracle.verdict);
    let artifact = AepaDifferentialArtifact {
        schema_version: AEPA_DIFFERENTIAL_VERSION.to_owned(),
        evaluator_version: AEPA_DIFFERENTIAL_VERSION.to_owned(),
        source_digest_sha256: hex(compiled.binding().source_digest.as_bytes()),
        transition_digest_sha256: hex(compiled.binding().transition_digest.as_bytes()),
        sequence_digest_sha256: hex(sequence.digest().as_bytes()),
        hardware_status: HARDWARE_STATUS.to_owned(),
        evidence_origin: AepaDifferentialEvidenceOrigin::ExecutedSoftware,
        injection_label: None,
        engine_digests: engine_digests.clone(),
        source_transitions: expected_source_transitions(compiled),
        verdict,
        source_reference,
        source_refinement,
        oracle,
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn build_aepa_injected_fixture_artifact(
    base: &AepaDifferentialArtifact,
    oracle: DifferentialOracleArtifact,
    injection_label: impl Into<String>,
) -> Result<AepaDifferentialArtifact, AepaDifferentialError> {
    base.validate()?;
    let injection_label = injection_label.into();
    if !valid_injection_label(&injection_label) {
        return Err(AepaDifferentialError::InjectionLabel);
    }
    let source_refinement = source_refinement(
        base.source_reference.as_ref(),
        &oracle.reference,
        base.source_refinement.unresolved_reason.clone(),
    )?;
    let mut artifact = base.clone();
    artifact.evidence_origin = AepaDifferentialEvidenceOrigin::InjectedTestFixture;
    artifact.injection_label = Some(injection_label);
    artifact.verdict = aggregate_verdict(source_refinement.verdict, oracle.verdict);
    artifact.source_refinement = source_refinement;
    artifact.oracle = oracle;
    artifact.validate()?;
    Ok(artifact)
}

fn expected_source_transitions(compiled: &AepaCompiledQsm) -> Vec<AepaExpectedTransition> {
    compiled
        .transitions()
        .iter()
        .map(|transition| AepaExpectedTransition {
            source_state: transition.source_state as u8,
            public_input: transition.public_input as u8,
            target_state: transition.target_state as u8,
            public_output: transition.public_output as u8,
        })
        .collect()
}

fn source_transitions_are_canonical(
    transitions: &[AepaExpectedTransition],
    expected_digest: &str,
) -> bool {
    if transitions.len() != AepaPublicState::ALL.len() * AepaPublicInput::ALL.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    let mut lowered = Vec::with_capacity(transitions.len());
    for transition in transitions {
        let Some(source_state) = decode_state(transition.source_state) else {
            return false;
        };
        let Some(public_input) = decode_input(transition.public_input) else {
            return false;
        };
        let Some(target_state) = decode_state(transition.target_state) else {
            return false;
        };
        let Some(public_output) = decode_output(transition.public_output) else {
            return false;
        };
        if !seen.insert((source_state, public_input)) {
            return false;
        }
        lowered.push(AepaLoweredTransition {
            source_state,
            public_input,
            target_state,
            public_output,
        });
    }
    lowered.sort_by_key(|transition| (transition.source_state, transition.public_input));
    let canonical = lowered.iter().enumerate().all(|(index, transition)| {
        let state_index = index / AepaPublicInput::ALL.len();
        let input_index = index % AepaPublicInput::ALL.len();
        transition.source_state == AepaPublicState::ALL[state_index]
            && transition.public_input == AepaPublicInput::ALL[input_index]
    });
    canonical && hex(aepa_transition_digest(&lowered).as_bytes()) == expected_digest
}

fn evidence_origin_is_valid(
    origin: AepaDifferentialEvidenceOrigin,
    injection_label: Option<&str>,
) -> bool {
    match (origin, injection_label) {
        (AepaDifferentialEvidenceOrigin::ExecutedSoftware, None) => true,
        (AepaDifferentialEvidenceOrigin::InjectedTestFixture, Some(label)) => {
            valid_injection_label(label)
        }
        _ => false,
    }
}

fn valid_injection_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn validate_commands(commands: &[ContextCommand]) -> Result<(), AepaDifferentialError> {
    let mut stopped = false;
    for command in commands {
        if stopped {
            return Err(AepaDifferentialError::CommandAfterStop);
        }
        if command.kind != command.family.command_kind() || command.payload_tag != 0 {
            return Err(AepaDifferentialError::NonCanonicalCommand);
        }
        match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => {
                let input = decode_input(command.fault)
                    .ok_or(AepaDifferentialError::NonCanonicalCommand)?;
                if command.service_alias == 0
                    || command.public_slot > u64::from(u32::MAX)
                    || !input_family_matches(input, command.family)
                {
                    return Err(AepaDifferentialError::NonCanonicalCommand);
                }
            }
            CommandKind::PublicReset | CommandKind::PublicHandoff | CommandKind::Stop => {
                if command.service_alias != 0 || command.public_slot != 0 || command.fault != 0 {
                    return Err(AepaDifferentialError::NonCanonicalCommand);
                }
            }
        }
        stopped = command.kind == CommandKind::Stop;
    }
    Ok(())
}

const fn input_family_matches(input: AepaPublicInput, family: ContextFamily) -> bool {
    match input {
        AepaPublicInput::PublicTick
        | AepaPublicInput::ValidatedAdmission
        | AepaPublicInput::Reset
        | AepaPublicInput::Handoff => matches!(family, ContextFamily::Tick),
        AepaPublicInput::Replay => matches!(family, ContextFamily::CrossServiceReplay),
        AepaPublicInput::Expired => matches!(family, ContextFamily::Deadline),
        AepaPublicInput::Downgrade | AepaPublicInput::WrongBinding => {
            matches!(family, ContextFamily::ServiceCollusion)
        }
        AepaPublicInput::Fault => matches!(family, ContextFamily::FaultTimeout),
    }
}

fn decode_state(code: u8) -> Option<AepaPublicState> {
    match code {
        0 => Some(AepaPublicState::Waiting),
        1 => Some(AepaPublicState::Admitted),
        2 => Some(AepaPublicState::CoverRequired),
        3 => Some(AepaPublicState::Faulted),
        _ => None,
    }
}

fn decode_input(code: u8) -> Option<AepaPublicInput> {
    match code {
        0 => Some(AepaPublicInput::PublicTick),
        1 => Some(AepaPublicInput::ValidatedAdmission),
        2 => Some(AepaPublicInput::Replay),
        3 => Some(AepaPublicInput::Expired),
        4 => Some(AepaPublicInput::Downgrade),
        5 => Some(AepaPublicInput::WrongBinding),
        6 => Some(AepaPublicInput::Reset),
        7 => Some(AepaPublicInput::Handoff),
        8 => Some(AepaPublicInput::Fault),
        _ => None,
    }
}

fn decode_output(code: u8) -> Option<AepaPublicOutput> {
    match code {
        0 => Some(AepaPublicOutput::Cover),
        1 => Some(AepaPublicOutput::AdmitOnce),
        2 => Some(AepaPublicOutput::Reject),
        3 => Some(AepaPublicOutput::Fault),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum PlannedHostCall {
    Frame { label: u32, slot: u64 },
    Action { action: u32, slot: u32 },
    Failure { code: i32 },
}

struct TickPlan {
    calls: Vec<PlannedHostCall>,
    next_state: AepaPublicState,
    next_cursor: u64,
}

fn plan_tick(
    compiled: &AepaCompiledQsm,
    state: AepaPublicState,
    cursor: u64,
    command: &ContextCommand,
) -> Result<TickPlan, AepaDifferentialError> {
    if command.service_alias != compiled.service_code().qsm_alias {
        return Ok(TickPlan {
            calls: vec![PlannedHostCall::Failure {
                code: AEPA_UNKNOWN_PUBLIC_SERVICE,
            }],
            next_state: state,
            next_cursor: cursor,
        });
    }
    if command.public_slot != cursor.wrapping_add(1) {
        return Ok(TickPlan {
            calls: vec![PlannedHostCall::Failure {
                code: AEPA_OUT_OF_ORDER_PUBLIC_STEP,
            }],
            next_state: state,
            next_cursor: cursor,
        });
    }
    let Some(input) = decode_input(command.fault) else {
        return Ok(TickPlan {
            calls: vec![PlannedHostCall::Failure {
                code: AEPA_UNKNOWN_PUBLIC_INPUT,
            }],
            next_state: state,
            next_cursor: cursor,
        });
    };
    let transition = compiled
        .transitions()
        .iter()
        .find(|transition| transition.source_state == state && transition.public_input == input)
        .ok_or(AepaDifferentialError::TransitionCoverage)?;
    let mut calls = vec![PlannedHostCall::Frame {
        label: command.service_alias,
        slot: command.public_slot,
    }];
    match transition.public_output {
        AepaPublicOutput::Cover => {}
        AepaPublicOutput::AdmitOnce => calls.push(PlannedHostCall::Action {
            action: compiled.admission_action(),
            slot: u32::try_from(command.public_slot)
                .map_err(|_| AepaDifferentialError::Arithmetic)?,
        }),
        AepaPublicOutput::Reject => calls.push(PlannedHostCall::Failure {
            code: AEPA_PUBLIC_REJECT,
        }),
        AepaPublicOutput::Fault => calls.push(PlannedHostCall::Failure {
            code: AEPA_PUBLIC_FAULT,
        }),
    }
    Ok(TickPlan {
        calls,
        next_state: transition.target_state,
        next_cursor: command.public_slot,
    })
}

fn expected_host_tape(
    compiled: &AepaCompiledQsm,
    commands: &[ContextCommand],
) -> Result<PublicHostTape, AepaDifferentialError> {
    let mut directives = Vec::new();
    let mut state = AepaPublicState::Waiting;
    let mut cursor = u64::MAX;
    for command in commands {
        match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => {
                let plan = plan_tick(compiled, state, cursor, command)?;
                for call in &plan.calls {
                    directives.push(HostDirective::new(
                        match call {
                            PlannedHostCall::Frame { .. } => "qseal.emit_frame",
                            PlannedHostCall::Action { .. } => "qseal.emit_action",
                            PlannedHostCall::Failure { .. } => "qseal.public_failure",
                        },
                        HostOutcome::Continue,
                    ));
                }
                state = plan.next_state;
                cursor = plan.next_cursor;
            }
            CommandKind::PublicReset => {
                state = AepaPublicState::Waiting;
                cursor = u64::MAX;
            }
            CommandKind::PublicHandoff => state = AepaPublicState::Waiting,
            CommandKind::Stop => {}
        }
    }
    Ok(PublicHostTape::new(directives))
}

enum SourceReferenceVerdict {
    Executed(Box<EngineRunArtifact>),
    Unresolved(String),
}

fn evaluate_source_reference(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
) -> Result<SourceReferenceVerdict, AepaDifferentialError> {
    let required_host_calls = u64::try_from(sequence.host_tape().directives().len())
        .map_err(|_| AepaDifferentialError::Arithmetic)?;
    if required_host_calls > sequence.limits().max_host_calls {
        return Ok(SourceReferenceVerdict::Unresolved(format!(
            "SOURCE_HOST_CALL_BOUND:required={required_host_calls}:limit={}",
            sequence.limits().max_host_calls
        )));
    }
    let (trace, termination) = expected_trace(compiled, sequence)?;
    let input = ExecutionInput {
        module_sha256: sha256_hex(compiled.wasm()),
        abi_sha256: hex(quotient_seal_abi_v1_hash().as_bytes()),
        engine: source_reference_identity(compiled),
        host_tape: HostTapeRecord::from(sequence.host_tape()),
        context_sequence: sequence
            .commands()
            .iter()
            .map(ContextCommandRecord::from)
            .collect(),
        limits: sequence.limits(),
    };
    let run = EngineRunArtifact::new(input, trace, termination, EngineRunVerdict::Executed)
        .map_err(|error| AepaDifferentialError::EngineContract(error.to_string()))?;
    Ok(SourceReferenceVerdict::Executed(Box::new(run)))
}

fn expected_trace(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
) -> Result<(Vec<ObservableEvent>, ExecutionTermination), AepaDifferentialError> {
    let mut trace = Vec::new();
    let mut state = AepaPublicState::Waiting;
    let mut cursor = u64::MAX;
    let mut final_values = Vec::new();
    for command in sequence.commands() {
        if command.kind == CommandKind::Stop {
            return Ok((trace, ExecutionTermination::Terminated));
        }
        final_values = match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => {
                let export = "qseal.public.tick";
                trace.push(ObservableEvent::ApiCall {
                    export: export.to_owned(),
                    arguments: vec![
                        ScalarValue::I32 {
                            bits: command.service_alias,
                        },
                        ScalarValue::I64 {
                            bits: command.public_slot,
                        },
                        ScalarValue::I32 {
                            bits: u32::from(command.fault),
                        },
                    ],
                });
                let plan = plan_tick(compiled, state, cursor, command)?;
                for call in &plan.calls {
                    append_planned_host_call(&mut trace, *call);
                }
                state = plan.next_state;
                cursor = plan.next_cursor;
                let values = vec![ScalarValue::I32 { bits: 0 }];
                trace.push(ObservableEvent::ApiReturn {
                    export: export.to_owned(),
                    values: values.clone(),
                });
                values
            }
            CommandKind::PublicReset => {
                let export = "qseal.public.reset";
                trace.push(ObservableEvent::ApiCall {
                    export: export.to_owned(),
                    arguments: Vec::new(),
                });
                state = AepaPublicState::Waiting;
                cursor = u64::MAX;
                trace.push(ObservableEvent::Reset { return_code: 0 });
                let values = vec![ScalarValue::I32 { bits: 0 }];
                trace.push(ObservableEvent::ApiReturn {
                    export: export.to_owned(),
                    values: values.clone(),
                });
                values
            }
            CommandKind::PublicHandoff => {
                let export = "qseal.public.handoff";
                trace.push(ObservableEvent::ApiCall {
                    export: export.to_owned(),
                    arguments: Vec::new(),
                });
                state = AepaPublicState::Waiting;
                trace.push(ObservableEvent::Handoff { value: cursor });
                let values = vec![ScalarValue::I64 { bits: cursor }];
                trace.push(ObservableEvent::ApiReturn {
                    export: export.to_owned(),
                    values: values.clone(),
                });
                values
            }
            CommandKind::Stop => unreachable!("handled above"),
        };
        append_public_state_probe(&mut trace, state);
    }
    Ok((
        trace,
        ExecutionTermination::Returned {
            values: final_values,
        },
    ))
}

fn append_planned_host_call(trace: &mut Vec<ObservableEvent>, call: PlannedHostCall) {
    match call {
        PlannedHostCall::Frame { label, slot } => {
            trace.push(ObservableEvent::HostImport {
                import: "qseal.emit_frame".to_owned(),
                arguments: vec![
                    ScalarValue::I32 { bits: label },
                    ScalarValue::I64 { bits: slot },
                ],
                outcome: HostOutcomeRecord::Continue,
            });
            trace.push(ObservableEvent::EmitFrame {
                label,
                slot,
                value: 0,
            });
        }
        PlannedHostCall::Action { action, slot } => {
            trace.push(ObservableEvent::HostImport {
                import: "qseal.emit_action".to_owned(),
                arguments: vec![
                    ScalarValue::I32 { bits: action },
                    ScalarValue::I32 { bits: slot },
                ],
                outcome: HostOutcomeRecord::Continue,
            });
            trace.push(ObservableEvent::EmitAction {
                action,
                slot: u64::from(slot),
                return_code: 0,
            });
        }
        PlannedHostCall::Failure { code } => {
            trace.push(ObservableEvent::HostImport {
                import: "qseal.public_failure".to_owned(),
                arguments: vec![ScalarValue::I32 { bits: code as u32 }],
                outcome: HostOutcomeRecord::Continue,
            });
            trace.push(ObservableEvent::PublicFailure { code });
        }
    }
}

fn append_public_state_probe(trace: &mut Vec<ObservableEvent>, state: AepaPublicState) {
    let bits = state as u32;
    trace.push(ObservableEvent::ApiCall {
        export: "qseal.public.status".to_owned(),
        arguments: Vec::new(),
    });
    trace.push(ObservableEvent::ApiReturn {
        export: "qseal.public.status".to_owned(),
        values: vec![ScalarValue::I32 { bits }],
    });
    trace.push(ObservableEvent::PublicState {
        digest_sha256: sha256_hex(&bits.to_le_bytes()),
    });
}

fn sequence_digest(
    compiled: &AepaCompiledQsm,
    commands: &[ContextCommand],
    host_tape: &PublicHostTape,
    limits: ExecutionLimits,
) -> Result<Digest, AepaDifferentialError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SEQUENCE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(compiled.binding().source_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().transition_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().module_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().capsule_digest.as_bytes());
    bytes.extend_from_slice(quotient_seal_abi_v1_hash().as_bytes());
    bytes.extend_from_slice(&limits.fuel.to_le_bytes());
    bytes.extend_from_slice(&limits.max_memory_pages.to_le_bytes());
    bytes.extend_from_slice(&limits.max_host_calls.to_le_bytes());
    bytes.extend_from_slice(&limits.timeout_ms.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(commands.len())
            .map_err(|_| AepaDifferentialError::Arithmetic)?
            .to_le_bytes(),
    );
    for command in commands {
        bytes.push(command.family as u8);
        bytes.push(command.kind as u8);
        bytes.extend_from_slice(&command.service_alias.to_le_bytes());
        bytes.extend_from_slice(&command.public_slot.to_le_bytes());
        bytes.push(command.fault);
        bytes.extend_from_slice(&command.payload_tag.to_le_bytes());
    }
    bytes.extend_from_slice(
        &u32::try_from(host_tape.directives().len())
            .map_err(|_| AepaDifferentialError::Arithmetic)?
            .to_le_bytes(),
    );
    for directive in host_tape.directives() {
        let import = directive.import().as_bytes();
        bytes.extend_from_slice(
            &u16::try_from(import.len())
                .map_err(|_| AepaDifferentialError::Arithmetic)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(import);
        bytes.push(match directive.outcome() {
            HostOutcome::Continue => 0,
            HostOutcome::Terminate => 1,
            HostOutcome::Fault(_) => 2,
        });
    }
    Ok(artifact_digest(SEQUENCE_DIGEST_DOMAIN, &bytes))
}

fn source_reference_identity(compiled: &AepaCompiledQsm) -> EngineIdentity {
    let executable = artifact_digest(
        REFERENCE_EXECUTABLE_DOMAIN,
        SOURCE_REFERENCE_VERSION.as_bytes(),
    );
    EngineIdentity {
        name: "noticer-aepa-source-reference".to_owned(),
        version: SOURCE_REFERENCE_VERSION.to_owned(),
        executable_sha256: hex(executable.as_bytes()),
        adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
        configuration: BTreeMap::from([
            (
                "reference_kind".to_owned(),
                "SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER".to_owned(),
            ),
            (
                "source_digest".to_owned(),
                hex(compiled.binding().source_digest.as_bytes()),
            ),
            (
                "transition_digest".to_owned(),
                hex(compiled.binding().transition_digest.as_bytes()),
            ),
            ("hardware_status".to_owned(), HARDWARE_STATUS.to_owned()),
        ]),
    }
}

fn validate_host_tape_shape(
    expected: &PublicHostTape,
    actual: &PublicHostTape,
) -> Result<(), AepaDifferentialError> {
    if expected.directives().len() != actual.directives().len()
        || expected
            .directives()
            .iter()
            .zip(actual.directives())
            .any(|(left, right)| left.import() != right.import())
    {
        Err(AepaDifferentialError::HostTapeShape)
    } else {
        Ok(())
    }
}

fn project_source_reference(
    base: &EngineRunArtifact,
    host_tape: &PublicHostTape,
) -> Result<EngineRunArtifact, AepaDifferentialError> {
    let mut trace = Vec::with_capacity(base.trace.len());
    let mut directive_index = 0_usize;
    let mut termination = base.termination.clone();
    for event in &base.trace {
        let ObservableEvent::HostImport {
            import, arguments, ..
        } = event
        else {
            trace.push(event.clone());
            continue;
        };
        let directive = host_tape
            .directives()
            .get(directive_index)
            .ok_or(AepaDifferentialError::HostTapeShape)?;
        if directive.import() != import {
            return Err(AepaDifferentialError::HostTapeShape);
        }
        directive_index = directive_index
            .checked_add(1)
            .ok_or(AepaDifferentialError::ArtifactContract)?;
        let outcome = directive.outcome();
        trace.push(ObservableEvent::HostImport {
            import: import.clone(),
            arguments: arguments.clone(),
            outcome: HostOutcomeRecord::from(outcome),
        });
        match outcome {
            HostOutcome::Continue => {}
            HostOutcome::Terminate => {
                termination = ExecutionTermination::Terminated;
                break;
            }
            HostOutcome::Fault(fault) => {
                termination = host_fault_termination(fault);
                break;
            }
        }
    }
    let mut input = base.input.clone();
    input.host_tape = HostTapeRecord::from(host_tape);
    make_run(input, trace, termination, EngineRunVerdict::Executed)
}

fn execute_small_step(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
    host_tape: &PublicHostTape,
    executable_sha256: &str,
) -> Result<EngineRunArtifact, AepaDifferentialError> {
    let input = small_step_input(compiled, sequence, host_tape, executable_sha256);
    let module = match parse_and_lower(compiled.wasm(), ParserLimits::default()) {
        Ok(module) => module,
        Err(error) => {
            return make_run(
                input,
                Vec::new(),
                ExecutionTermination::Unsupported {
                    feature: format!("TARGET_IR:{error:?}"),
                },
                EngineRunVerdict::Unresolved,
            )
        }
    };
    let runtime_tape = small_step_tape(host_tape)?;
    let mut runtime = SmallStepRuntime::new(&module, runtime_tape, sequence.limits());
    let mut trace = Vec::new();
    let mut final_values = Vec::new();
    let mut termination = None;
    for command in sequence.commands() {
        if command.kind == CommandKind::Stop {
            termination = Some(ExecutionTermination::Terminated);
            break;
        }
        let (export, arguments) = command_invocation(command);
        trace.push(ObservableEvent::ApiCall {
            export: export.to_owned(),
            arguments: scalar_values(&arguments),
        });
        let invocation = match runtime.invoke(export, arguments) {
            Ok(invocation) => invocation,
            Err(detail) => {
                termination = Some(engine_failure("small_step_invoke", &detail));
                break;
            }
        };
        if let Err(detail) = append_host_events(&mut trace, &invocation.events) {
            termination = Some(engine_failure("small_step_host_trace", &detail));
            break;
        }
        match invocation.status {
            MachineStatus::Returned(values) => {
                final_values = scalar_values(&values);
                append_lifecycle_event(&mut trace, command.kind, &values)?;
                trace.push(ObservableEvent::ApiReturn {
                    export: export.to_owned(),
                    values: final_values.clone(),
                });
            }
            status => {
                termination = Some(machine_termination(&status, sequence.limits()));
                break;
            }
        }
        let status_export = "qseal.public.status";
        trace.push(ObservableEvent::ApiCall {
            export: status_export.to_owned(),
            arguments: Vec::new(),
        });
        let status_invocation = match runtime.invoke(status_export, Vec::new()) {
            Ok(invocation) => invocation,
            Err(detail) => {
                termination = Some(engine_failure("small_step_status", &detail));
                break;
            }
        };
        if let Err(detail) = append_host_events(&mut trace, &status_invocation.events) {
            termination = Some(engine_failure("small_step_status_trace", &detail));
            break;
        }
        match status_invocation.status {
            MachineStatus::Returned(values) => {
                let Some(Value::I32(state)) = values.first() else {
                    termination = Some(engine_failure(
                        "small_step_status_shape",
                        "status did not return one i32 value",
                    ));
                    break;
                };
                trace.push(ObservableEvent::ApiReturn {
                    export: status_export.to_owned(),
                    values: scalar_values(&values),
                });
                trace.push(ObservableEvent::PublicState {
                    digest_sha256: sha256_hex(&state.to_le_bytes()),
                });
            }
            status => {
                termination = Some(machine_termination(&status, sequence.limits()));
                break;
            }
        }
    }
    let termination = termination.unwrap_or(ExecutionTermination::Returned {
        values: final_values,
    });
    let verdict = if matches!(
        termination,
        ExecutionTermination::Unsupported { .. }
            | ExecutionTermination::TimedOut { .. }
            | ExecutionTermination::ResourceExhausted { .. }
            | ExecutionTermination::EngineFailure { .. }
    ) {
        EngineRunVerdict::Unresolved
    } else {
        EngineRunVerdict::Executed
    };
    make_run(input, trace, termination, verdict)
}

struct SmallStepRuntime<'a> {
    module: &'a CanonicalTargetIr,
    host_tape: PublicHostTape,
    limits: ExecutionLimits,
    consumed_host_directives: usize,
    remaining_fuel: u64,
    seed: CheckerSeed,
    initialized: bool,
}

impl<'a> SmallStepRuntime<'a> {
    fn new(
        module: &'a CanonicalTargetIr,
        host_tape: PublicHostTape,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            module,
            host_tape,
            limits,
            consumed_host_directives: 0,
            remaining_fuel: limits.fuel,
            seed: CheckerSeed::default(),
            initialized: false,
        }
    }

    fn invoke(&mut self, export: &str, arguments: Vec<Value>) -> Result<Invocation, String> {
        let canonical_export = export.strip_prefix("qseal.public.").unwrap_or(export);
        let tape = PublicHostTape::new(
            self.host_tape.directives()[self.consumed_host_directives..].to_vec(),
        );
        let interpreter_limits = interpreter_limits(self.limits, self.consumed_host_directives);
        let machine = if self.initialized {
            WasmMachine::instantiate_for_checker(
                self.module,
                canonical_export,
                arguments,
                self.remaining_fuel,
                tape,
                interpreter_limits,
                &self.seed,
            )
            .map_err(|error| format!("checker seed failure: {error:?}"))?
        } else {
            WasmMachine::instantiate(
                self.module,
                canonical_export,
                arguments,
                self.remaining_fuel,
                tape,
                interpreter_limits,
            )
            .map_err(|error| format!("instantiation failure: {error:?}"))?
        };
        let report = machine.run();
        self.consumed_host_directives = self
            .consumed_host_directives
            .checked_add(report.consumed_host_directives())
            .ok_or_else(|| "host tape cursor overflow".to_owned())?;
        let state = report.state();
        self.remaining_fuel = state.fuel();
        self.seed.globals = state
            .globals()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, value)| {
                u32::try_from(index)
                    .map(|index| (index, value))
                    .map_err(|_| "global index overflow".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.seed.memory = if state.memory().is_empty() {
            Vec::new()
        } else {
            vec![CheckerMemoryPatch {
                offset: 0,
                bytes: state.memory().to_vec(),
            }]
        };
        self.initialized = true;
        Ok(Invocation {
            status: state.status().clone(),
            events: state.events().to_vec(),
        })
    }
}

struct Invocation {
    status: MachineStatus,
    events: Vec<ExecutionEvent>,
}

fn small_step_input(
    compiled: &AepaCompiledQsm,
    sequence: &AepaPublicSequence,
    host_tape: &PublicHostTape,
    executable_sha256: &str,
) -> ExecutionInput {
    ExecutionInput {
        module_sha256: sha256_hex(compiled.wasm()),
        abi_sha256: hex(quotient_seal_abi_v1_hash().as_bytes()),
        engine: EngineIdentity {
            name: REFERENCE_ENGINE_NAME.to_owned(),
            version: QUOTIENT_SEAL_SMALL_STEP_V1.to_owned(),
            executable_sha256: executable_sha256.to_owned(),
            adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
            configuration: BTreeMap::from([
                (
                    "adapter_profile".to_owned(),
                    SMALL_STEP_ADAPTER_VERSION.to_owned(),
                ),
                (
                    "state_carry".to_owned(),
                    "CHECKER_SEED_GLOBALS_AND_MEMORY".to_owned(),
                ),
                ("hardware_status".to_owned(), HARDWARE_STATUS.to_owned()),
            ]),
        },
        host_tape: HostTapeRecord::from(host_tape),
        context_sequence: sequence
            .commands()
            .iter()
            .map(ContextCommandRecord::from)
            .collect(),
        limits: sequence.limits(),
    }
}

fn small_step_tape(host_tape: &PublicHostTape) -> Result<PublicHostTape, AepaDifferentialError> {
    let directives = host_tape
        .directives()
        .iter()
        .map(|directive| {
            let import = directive
                .import()
                .strip_prefix("qseal.")
                .ok_or(AepaDifferentialError::HostImportContract)?;
            Ok(HostDirective::new(import, directive.outcome()))
        })
        .collect::<Result<Vec<_>, AepaDifferentialError>>()?;
    Ok(PublicHostTape::new(directives))
}

fn interpreter_limits(limits: ExecutionLimits, consumed_host_calls: usize) -> InterpreterLimits {
    let max_memory_bytes = usize::try_from(limits.max_memory_pages)
        .ok()
        .and_then(|pages| pages.checked_mul(65_536))
        .unwrap_or(usize::MAX);
    let total_host_calls = usize::try_from(limits.max_host_calls).unwrap_or(usize::MAX);
    let max_events = usize::try_from(limits.fuel)
        .ok()
        .and_then(|fuel| fuel.checked_mul(8))
        .and_then(|events| events.checked_add(1_024))
        .unwrap_or(usize::MAX);
    InterpreterLimits {
        max_initial_fuel: limits.fuel,
        max_events,
        max_operand_stack: 4_096,
        max_call_depth: 256,
        max_memory_bytes,
        max_host_calls: total_host_calls.saturating_sub(consumed_host_calls),
    }
}

fn command_invocation(command: &ContextCommand) -> (&'static str, Vec<Value>) {
    match command.kind {
        CommandKind::PublicCall | CommandKind::PublicFault => (
            "qseal.public.tick",
            vec![
                Value::I32(command.service_alias),
                Value::I64(command.public_slot),
                Value::I32(u32::from(command.fault)),
            ],
        ),
        CommandKind::PublicReset => ("qseal.public.reset", Vec::new()),
        CommandKind::PublicHandoff => ("qseal.public.handoff", Vec::new()),
        CommandKind::Stop => unreachable!("Stop has no Wasm export"),
    }
}

fn append_lifecycle_event(
    trace: &mut Vec<ObservableEvent>,
    kind: CommandKind,
    values: &[Value],
) -> Result<(), AepaDifferentialError> {
    match kind {
        CommandKind::PublicReset => match values {
            [Value::I32(return_code)] => trace.push(ObservableEvent::Reset {
                return_code: *return_code as i32,
            }),
            _ => return Err(AepaDifferentialError::ReturnShape("reset")),
        },
        CommandKind::PublicHandoff => match values {
            [Value::I64(value)] => trace.push(ObservableEvent::Handoff { value: *value }),
            _ => return Err(AepaDifferentialError::ReturnShape("handoff")),
        },
        CommandKind::PublicCall | CommandKind::PublicFault => {}
        CommandKind::Stop => unreachable!("Stop has no lifecycle return"),
    }
    Ok(())
}

fn append_host_events(
    trace: &mut Vec<ObservableEvent>,
    events: &[ExecutionEvent],
) -> Result<(), String> {
    for event in events {
        let ExecutionEvent::HostCall {
            import,
            arguments,
            outcome,
            ..
        } = event
        else {
            continue;
        };
        let qualified = format!("qseal.{import}");
        trace.push(ObservableEvent::HostImport {
            import: qualified,
            arguments: scalar_values(arguments),
            outcome: HostOutcomeRecord::from(*outcome),
        });
        if *outcome != HostOutcome::Continue {
            continue;
        }
        match (import.as_str(), arguments.as_slice()) {
            ("emit_frame", [Value::I32(label), Value::I64(slot)]) => {
                trace.push(ObservableEvent::EmitFrame {
                    label: *label,
                    slot: *slot,
                    value: 0,
                });
            }
            ("emit_action", [Value::I32(action), Value::I32(slot)]) => {
                trace.push(ObservableEvent::EmitAction {
                    action: *action,
                    slot: u64::from(*slot),
                    return_code: 0,
                });
            }
            ("public_failure", [Value::I32(code)]) => {
                trace.push(ObservableEvent::PublicFailure { code: *code as i32 });
            }
            _ => return Err(format!("unexpected host call shape: {import}")),
        }
    }
    Ok(())
}

fn scalar_values(values: &[Value]) -> Vec<ScalarValue> {
    values
        .iter()
        .map(|value| match value {
            Value::I32(bits) => ScalarValue::I32 { bits: *bits },
            Value::I64(bits) => ScalarValue::I64 { bits: *bits },
        })
        .collect()
}

fn machine_termination(status: &MachineStatus, limits: ExecutionLimits) -> ExecutionTermination {
    match status {
        MachineStatus::Returned(values) => ExecutionTermination::Returned {
            values: scalar_values(values),
        },
        MachineStatus::Terminated => ExecutionTermination::Terminated,
        MachineStatus::Trapped(code) => trap_termination(*code),
        MachineStatus::ResourceBound(resource) => resource_termination(*resource, limits),
        MachineStatus::Running => engine_failure("small_step_status", "machine remained running"),
    }
}

fn trap_termination(code: TrapCode) -> ExecutionTermination {
    if let TrapCode::HostFault(fault) = code {
        return host_fault_termination(fault);
    }
    let class = match code {
        TrapCode::Unreachable => TrapClass::Unreachable,
        TrapCode::IntegerDivideByZero => TrapClass::IntegerDivideByZero,
        TrapCode::IntegerOverflow => TrapClass::IntegerOverflow,
        TrapCode::MemoryOutOfBounds => TrapClass::MemoryOutOfBounds,
        TrapCode::InvalidConversion => TrapClass::InvalidConversion,
        _ => TrapClass::EngineSpecific,
    };
    let detail = format!("{code:?}");
    ExecutionTermination::Trapped {
        class,
        engine_code: detail.clone(),
        detail_sha256: sha256_hex(detail.as_bytes()),
    }
}

fn host_fault_termination(fault: PublicHostFault) -> ExecutionTermination {
    let code = match fault {
        PublicHostFault::Timeout => "HOST_TIMEOUT",
        PublicHostFault::Reconnect => "HOST_RECONNECT",
        PublicHostFault::Loss => "HOST_LOSS",
        PublicHostFault::Denied => "HOST_DENIED",
    };
    ExecutionTermination::Trapped {
        class: TrapClass::HostFault,
        engine_code: code.to_owned(),
        detail_sha256: sha256_hex(code.as_bytes()),
    }
}

fn resource_termination(
    resource: ResourceExhaustion,
    limits: ExecutionLimits,
) -> ExecutionTermination {
    let (resource, limit, observed) = match resource {
        ResourceExhaustion::Fuel { needed, remaining } => (
            ResourceKind::Fuel,
            limits.fuel,
            Some(limits.fuel.saturating_sub(remaining).saturating_add(needed)),
        ),
        ResourceExhaustion::EventLog { limit } => (
            ResourceKind::EventLog,
            limit as u64,
            Some((limit as u64).saturating_add(1)),
        ),
        ResourceExhaustion::OperandStack { limit } => (
            ResourceKind::EventLog,
            limit as u64,
            Some((limit as u64).saturating_add(1)),
        ),
        ResourceExhaustion::CallDepth { limit } => (
            ResourceKind::CallDepth,
            limit as u64,
            Some((limit as u64).saturating_add(1)),
        ),
        ResourceExhaustion::Memory { limit, requested } => {
            (ResourceKind::Memory, limit as u64, Some(requested as u64))
        }
        ResourceExhaustion::HostCalls { limit } => (
            ResourceKind::HostCalls,
            limits.max_host_calls,
            Some((limit as u64).saturating_add(1)),
        ),
    };
    ExecutionTermination::ResourceExhausted {
        resource,
        limit,
        observed,
    }
}

fn engine_failure(stage: &str, detail: &str) -> ExecutionTermination {
    ExecutionTermination::EngineFailure {
        stage: stage.to_owned(),
        exit_code: None,
        detail_sha256: sha256_hex(detail.as_bytes()),
    }
}

fn make_run(
    input: ExecutionInput,
    trace: Vec<ObservableEvent>,
    termination: ExecutionTermination,
    verdict: EngineRunVerdict,
) -> Result<EngineRunArtifact, AepaDifferentialError> {
    EngineRunArtifact::new(input, trace, termination, verdict)
        .map_err(|error| AepaDifferentialError::EngineContract(error.to_string()))
}

fn source_refinement(
    source: Option<&EngineRunArtifact>,
    small_step: &EngineRunArtifact,
    unresolved_reason: Option<String>,
) -> Result<AepaSourceRefinement, AepaDifferentialError> {
    let Some(source) = source else {
        return Ok(AepaSourceRefinement {
            verdict: AepaDifferentialVerdict::Unresolved,
            first_difference: None,
            unresolved_reason: Some(
                unresolved_reason.unwrap_or_else(|| "SOURCE_REFERENCE_UNAVAILABLE".to_owned()),
            ),
        });
    };
    if !shared_input_matches(&source.input, &small_step.input) {
        return Err(AepaDifferentialError::SourceInputMismatch);
    }
    if source.verdict != EngineRunVerdict::Executed
        || small_step.verdict != EngineRunVerdict::Executed
    {
        return Ok(AepaSourceRefinement {
            verdict: AepaDifferentialVerdict::Unresolved,
            first_difference: None,
            unresolved_reason: Some("SOURCE_OR_SMALL_STEP_NOT_EXECUTED".to_owned()),
        });
    }
    if let Some(first_difference) = first_difference(source, small_step) {
        Ok(AepaSourceRefinement {
            verdict: AepaDifferentialVerdict::Counterexample,
            first_difference: Some(first_difference),
            unresolved_reason: None,
        })
    } else {
        Ok(AepaSourceRefinement {
            verdict: AepaDifferentialVerdict::Match,
            first_difference: None,
            unresolved_reason: None,
        })
    }
}

fn first_difference(
    left: &EngineRunArtifact,
    right: &EngineRunArtifact,
) -> Option<ComparisonPoint> {
    let trace_len = left.trace.len().max(right.trace.len());
    for index in 0..trace_len {
        let left_event = left.trace.get(index);
        let right_event = right.trace.get(index);
        if left_event != right_event {
            return Some(ComparisonPoint::Trace {
                index: index as u64,
                left_axis: left_event.map(event_axis),
                right_axis: right_event.map(event_axis),
                left: left_event.cloned(),
                right: right_event.cloned(),
            });
        }
    }
    if left.termination != right.termination {
        return Some(ComparisonPoint::Termination {
            left_axis: termination_axis(&left.termination),
            right_axis: termination_axis(&right.termination),
            left: left.termination.clone(),
            right: right.termination.clone(),
        });
    }
    None
}

fn event_axis(event: &ObservableEvent) -> ObservableAxis {
    match event {
        ObservableEvent::ApiCall { .. } | ObservableEvent::ApiReturn { .. } => {
            ObservableAxis::Return
        }
        ObservableEvent::EmitFrame { .. }
        | ObservableEvent::EmitAction { .. }
        | ObservableEvent::PublicFailure { .. } => ObservableAxis::Output,
        ObservableEvent::HostImport { .. } => ObservableAxis::HostImport,
        ObservableEvent::Reset { .. } => ObservableAxis::Reset,
        ObservableEvent::Handoff { .. } => ObservableAxis::Handoff,
        ObservableEvent::PublicState { .. } => ObservableAxis::PublicState,
    }
}

fn termination_axis(termination: &ExecutionTermination) -> ObservableAxis {
    if matches!(termination, ExecutionTermination::Trapped { .. }) {
        ObservableAxis::Trap
    } else {
        ObservableAxis::Return
    }
}

fn shared_input_matches(left: &ExecutionInput, right: &ExecutionInput) -> bool {
    left.module_sha256 == right.module_sha256
        && left.abi_sha256 == right.abi_sha256
        && left.host_tape == right.host_tape
        && left.context_sequence == right.context_sequence
        && left.limits == right.limits
}

const fn aggregate_verdict(
    source: AepaDifferentialVerdict,
    oracle: DifferentialVerdict,
) -> AepaDifferentialVerdict {
    match (source, oracle) {
        (AepaDifferentialVerdict::Unresolved, _) | (_, DifferentialVerdict::Unresolved) => {
            AepaDifferentialVerdict::Unresolved
        }
        (AepaDifferentialVerdict::Counterexample, _) | (_, DifferentialVerdict::Counterexample) => {
            AepaDifferentialVerdict::Counterexample
        }
        (AepaDifferentialVerdict::Match, DifferentialVerdict::Match) => {
            AepaDifferentialVerdict::Match
        }
    }
}

fn engine_digests_match(expected: &AepaEngineDigests, oracle: &DifferentialOracleArtifact) -> bool {
    oracle.reference.input.engine.executable_sha256 == expected.small_step_sha256()
        && oracle.engines.len() == 2
        && oracle.engines[0].input.engine.name == "wasmi"
        && oracle.engines[0].input.engine.executable_sha256 == expected.wasmi_sha256()
        && oracle.engines[1].input.engine.name == "wasmtime"
        && oracle.engines[1].input.engine.executable_sha256 == expected.wasmtime_sha256()
}

fn external_error(engine: &'static str, error: impl std::fmt::Display) -> AepaDifferentialError {
    AepaDifferentialError::ExternalEngine {
        engine,
        detail: error.to_string(),
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

#[derive(Debug, Error)]
pub enum AepaDifferentialError {
    #[error("invalid executable SHA-256 for {engine}")]
    InvalidExecutableDigest { engine: String },
    #[error("{engine} adapter failed: {detail}")]
    ExternalEngine {
        engine: &'static str,
        detail: String,
    },
    #[error("differential oracle failed: {0}")]
    Oracle(String),
    #[error("engine artifact contract failed: {0}")]
    EngineContract(String),
    #[error("AEPA differential artifact serialization failed: {0}")]
    Serialization(String),
    #[error("AEPA differential artifact violated its contract")]
    ArtifactContract,
    #[error("source and small-step inputs do not share the same public execution input")]
    SourceInputMismatch,
    #[error("small-step host import is not qseal-qualified")]
    HostImportContract,
    #[error("injected host tape must preserve the canonical import sequence")]
    HostTapeShape,
    #[error("AEPA public sequence command count is empty or exceeds the bound")]
    CommandCount,
    #[error("AEPA public sequence resource limits must be nonzero")]
    InvalidLimits,
    #[error("AEPA public sequence contains a non-canonical command")]
    NonCanonicalCommand,
    #[error("AEPA public sequence contains a command after Stop")]
    CommandAfterStop,
    #[error("AEPA compiled transition table is incomplete")]
    TransitionCoverage,
    #[error("AEPA differential arithmetic overflow")]
    Arithmetic,
    #[error("unexpected {0} return shape")]
    ReturnShape(&'static str),
    #[error("injected fixture label must be canonical and nonempty")]
    InjectionLabel,
}
