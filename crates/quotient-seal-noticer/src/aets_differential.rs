use std::collections::BTreeMap;

use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::{CommandKind, ContextCommand};
use quotient_seal_engine::{
    ComparisonPoint, ContextCommandRecord, DifferentialOracle, DifferentialOracleArtifact,
    DifferentialVerdict, EngineIdentity, EngineRunArtifact, EngineRunVerdict, ExecutionInput,
    ExecutionLimits, ExecutionTermination, HostOutcomeRecord, HostTapeRecord, ObservableAxis,
    ObservableEvent, ResourceKind, ScalarValue, TrapClass, WasmiAdapter, WasmtimeAdapter,
    ENGINE_ADAPTER_CONTRACT_VERSION, REFERENCE_ENGINE_NAME,
};
use quotient_seal_small_step::{
    CheckerMemoryPatch, CheckerSeed, ExecutionEvent, HostDirective, HostOutcome, InterpreterLimits,
    MachineStatus, PublicHostTape, ResourceExhaustion, TrapCode, Value, WasmMachine,
    QUOTIENT_SEAL_SMALL_STEP_V1,
};
use quotient_seal_target_ir::{parse_and_lower, CanonicalTargetIr, ParserLimits};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    evaluate_aets_source_reference, AetsCompiledQsm, AetsPublicSequence, AetsReferenceVerdict,
};

pub const AETS_DIFFERENTIAL_VERSION: &str = "noticer-aets-differential/v1";
const SMALL_STEP_ADAPTER_VERSION: &str = "noticer-aets-small-step-adapter/v1";
const HARDWARE_STATUS: &str = "NOT_VERIFIED";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsEngineDigests {
    small_step_sha256: String,
    wasmi_sha256: String,
    wasmtime_sha256: String,
}

impl AetsEngineDigests {
    pub fn new(
        small_step_sha256: impl Into<String>,
        wasmi_sha256: impl Into<String>,
        wasmtime_sha256: impl Into<String>,
    ) -> Result<Self, AetsDifferentialError> {
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
                return Err(AetsDifferentialError::InvalidExecutableDigest {
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
pub enum AetsDifferentialVerdict {
    Match,
    Counterexample,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsSourceRefinement {
    pub verdict: AetsDifferentialVerdict,
    pub first_difference: Option<ComparisonPoint>,
    pub unresolved_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AetsDifferentialArtifact {
    pub schema_version: String,
    pub evaluator_version: String,
    pub source_digest_sha256: String,
    pub sequence_digest_sha256: String,
    pub hardware_status: String,
    pub verdict: AetsDifferentialVerdict,
    pub source_reference: Option<EngineRunArtifact>,
    pub source_refinement: AetsSourceRefinement,
    pub oracle: DifferentialOracleArtifact,
}

impl AetsDifferentialArtifact {
    pub fn validate(&self) -> Result<(), AetsDifferentialError> {
        if self.schema_version != AETS_DIFFERENTIAL_VERSION
            || self.evaluator_version != AETS_DIFFERENTIAL_VERSION
            || self.hardware_status != HARDWARE_STATUS
            || !is_sha256(&self.source_digest_sha256)
            || !is_sha256(&self.sequence_digest_sha256)
        {
            return Err(AetsDifferentialError::ArtifactContract);
        }
        self.oracle
            .validate()
            .map_err(|error| AetsDifferentialError::Oracle(error.to_string()))?;

        let expected_refinement = source_refinement(
            self.source_reference.as_ref(),
            &self.oracle.reference,
            self.source_refinement.unresolved_reason.clone(),
        )?;
        if expected_refinement != self.source_refinement
            || aggregate_verdict(expected_refinement.verdict, self.oracle.verdict) != self.verdict
        {
            return Err(AetsDifferentialError::ArtifactContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AetsDifferentialError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| AetsDifferentialError::Serialization(error.to_string()))
    }

    pub fn artifact_sha256(&self) -> Result<String, AetsDifferentialError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }
}

pub fn evaluate_aets_differential(
    compiled: &AetsCompiledQsm,
    sequence: &AetsPublicSequence,
    engine_digests: &AetsEngineDigests,
) -> Result<AetsDifferentialArtifact, AetsDifferentialError> {
    let source_verdict = evaluate_aets_source_reference(compiled, sequence)
        .map_err(|error| AetsDifferentialError::SourceReference(error.to_string()))?;
    let (source_reference, source_unresolved) = match source_verdict {
        AetsReferenceVerdict::Executed(artifact) => (Some(artifact.run().clone()), None),
        AetsReferenceVerdict::Unresolved(reason) => (
            None,
            Some(format!("SOURCE_REFERENCE_UNRESOLVED:{reason:?}")),
        ),
    };

    let small_step = execute_small_step(compiled, sequence, engine_digests.small_step_sha256())?;
    let wasmi = WasmiAdapter::new(engine_digests.wasmi_sha256())
        .map_err(|error| external_error("wasmi", error))?
        .execute(
            compiled.wasm_module(),
            sequence.host_tape(),
            sequence.commands(),
            sequence.limits(),
        )
        .map_err(|error| external_error("wasmi", error))?;
    let wasmtime = WasmtimeAdapter::new(engine_digests.wasmtime_sha256())
        .map_err(|error| external_error("wasmtime", error))?
        .execute(
            compiled.wasm_module(),
            sequence.host_tape(),
            sequence.commands(),
            sequence.limits(),
        )
        .map_err(|error| external_error("wasmtime", error))?;
    let oracle = DifferentialOracle::evaluate(small_step, vec![wasmi, wasmtime])
        .map_err(|error| AetsDifferentialError::Oracle(error.to_string()))?;
    let source_refinement = source_refinement(
        source_reference.as_ref(),
        &oracle.reference,
        source_unresolved,
    )?;
    let verdict = aggregate_verdict(source_refinement.verdict, oracle.verdict);
    let artifact = AetsDifferentialArtifact {
        schema_version: AETS_DIFFERENTIAL_VERSION.to_owned(),
        evaluator_version: AETS_DIFFERENTIAL_VERSION.to_owned(),
        source_digest_sha256: hex(compiled.source_digest().as_bytes()),
        sequence_digest_sha256: hex(sequence.digest().as_bytes()),
        hardware_status: HARDWARE_STATUS.to_owned(),
        verdict,
        source_reference,
        source_refinement,
        oracle,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn execute_small_step(
    compiled: &AetsCompiledQsm,
    sequence: &AetsPublicSequence,
    executable_sha256: &str,
) -> Result<EngineRunArtifact, AetsDifferentialError> {
    let input = small_step_input(compiled, sequence, executable_sha256);
    let module = match parse_and_lower(compiled.wasm_module(), ParserLimits::default()) {
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
    let runtime_tape = small_step_tape(sequence.host_tape())?;
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
    compiled: &AetsCompiledQsm,
    sequence: &AetsPublicSequence,
    executable_sha256: &str,
) -> ExecutionInput {
    ExecutionInput {
        module_sha256: sha256_hex(compiled.wasm_module()),
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
        host_tape: HostTapeRecord::from(sequence.host_tape()),
        context_sequence: sequence
            .commands()
            .iter()
            .map(ContextCommandRecord::from)
            .collect(),
        limits: sequence.limits(),
    }
}

fn small_step_tape(host_tape: &PublicHostTape) -> Result<PublicHostTape, AetsDifferentialError> {
    let directives = host_tape
        .directives()
        .iter()
        .map(|directive| {
            let import = directive
                .import()
                .strip_prefix("qseal.")
                .ok_or(AetsDifferentialError::HostImportContract)?;
            Ok(HostDirective::new(import, directive.outcome()))
        })
        .collect::<Result<Vec<_>, AetsDifferentialError>>()?;
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
) -> Result<(), AetsDifferentialError> {
    match kind {
        CommandKind::PublicReset => match values {
            [Value::I32(return_code)] => trace.push(ObservableEvent::Reset {
                return_code: *return_code as i32,
            }),
            _ => return Err(AetsDifferentialError::ReturnShape("reset")),
        },
        CommandKind::PublicHandoff => match values {
            [Value::I64(value)] => trace.push(ObservableEvent::Handoff { value: *value }),
            _ => return Err(AetsDifferentialError::ReturnShape("handoff")),
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
    let class = match code {
        TrapCode::Unreachable => TrapClass::Unreachable,
        TrapCode::IntegerDivideByZero => TrapClass::IntegerDivideByZero,
        TrapCode::IntegerOverflow => TrapClass::IntegerOverflow,
        TrapCode::MemoryOutOfBounds => TrapClass::MemoryOutOfBounds,
        TrapCode::InvalidConversion => TrapClass::InvalidConversion,
        TrapCode::HostFault(_) => TrapClass::HostFault,
        _ => TrapClass::EngineSpecific,
    };
    let detail = format!("{code:?}");
    ExecutionTermination::Trapped {
        class,
        engine_code: detail.clone(),
        detail_sha256: sha256_hex(detail.as_bytes()),
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
) -> Result<EngineRunArtifact, AetsDifferentialError> {
    EngineRunArtifact::new(input, trace, termination, verdict)
        .map_err(|error| AetsDifferentialError::EngineContract(error.to_string()))
}

fn source_refinement(
    source: Option<&EngineRunArtifact>,
    small_step: &EngineRunArtifact,
    unresolved_reason: Option<String>,
) -> Result<AetsSourceRefinement, AetsDifferentialError> {
    let Some(source) = source else {
        return Ok(AetsSourceRefinement {
            verdict: AetsDifferentialVerdict::Unresolved,
            first_difference: None,
            unresolved_reason: Some(
                unresolved_reason.unwrap_or_else(|| "SOURCE_REFERENCE_UNAVAILABLE".to_owned()),
            ),
        });
    };
    if !shared_input_matches(&source.input, &small_step.input) {
        return Err(AetsDifferentialError::SourceInputMismatch);
    }
    if source.verdict != EngineRunVerdict::Executed
        || small_step.verdict != EngineRunVerdict::Executed
    {
        return Ok(AetsSourceRefinement {
            verdict: AetsDifferentialVerdict::Unresolved,
            first_difference: None,
            unresolved_reason: Some("SOURCE_OR_SMALL_STEP_NOT_EXECUTED".to_owned()),
        });
    }
    if let Some(first_difference) = first_difference(source, small_step) {
        Ok(AetsSourceRefinement {
            verdict: AetsDifferentialVerdict::Counterexample,
            first_difference: Some(first_difference),
            unresolved_reason: None,
        })
    } else {
        Ok(AetsSourceRefinement {
            verdict: AetsDifferentialVerdict::Match,
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
    source: AetsDifferentialVerdict,
    oracle: DifferentialVerdict,
) -> AetsDifferentialVerdict {
    match (source, oracle) {
        (AetsDifferentialVerdict::Unresolved, _) | (_, DifferentialVerdict::Unresolved) => {
            AetsDifferentialVerdict::Unresolved
        }
        (AetsDifferentialVerdict::Counterexample, _) | (_, DifferentialVerdict::Counterexample) => {
            AetsDifferentialVerdict::Counterexample
        }
        (AetsDifferentialVerdict::Match, DifferentialVerdict::Match) => {
            AetsDifferentialVerdict::Match
        }
    }
}

fn external_error(engine: &'static str, error: impl std::fmt::Display) -> AetsDifferentialError {
    AetsDifferentialError::ExternalEngine {
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
pub enum AetsDifferentialError {
    #[error("invalid executable SHA-256 for {engine}")]
    InvalidExecutableDigest { engine: String },
    #[error("AETS source reference failed: {0}")]
    SourceReference(String),
    #[error("{engine} adapter failed: {detail}")]
    ExternalEngine {
        engine: &'static str,
        detail: String,
    },
    #[error("differential oracle failed: {0}")]
    Oracle(String),
    #[error("engine artifact contract failed: {0}")]
    EngineContract(String),
    #[error("AETS differential artifact serialization failed: {0}")]
    Serialization(String),
    #[error("AETS differential artifact violated its contract")]
    ArtifactContract,
    #[error("source and small-step inputs do not share the same public execution input")]
    SourceInputMismatch,
    #[error("small-step host import is not qseal-qualified")]
    HostImportContract,
    #[error("unexpected {0} return shape")]
    ReturnShape(&'static str),
}
