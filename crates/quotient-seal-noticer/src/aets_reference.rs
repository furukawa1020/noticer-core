use std::collections::{BTreeMap, BTreeSet};

use quotient_forge_caqt::{artifact_digest, Digest};
use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ContextCommandRecord, EngineIdentity, EngineRunArtifact, EngineRunVerdict, ExecutionInput,
    ExecutionLimits, ExecutionTermination, HostOutcomeRecord, HostTapeRecord, ObservableEvent,
    ScalarValue, ENGINE_ADAPTER_CONTRACT_VERSION,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::aets_compile::{OUTSIDE_SCHEDULE_FAILURE, UNKNOWN_SERVICE_FAILURE};
use crate::AetsCompiledQsm;

pub const AETS_SOURCE_REFERENCE_VERSION: &str = "noticer-aets-source-reference/v1";
const SEQUENCE_MAGIC: &[u8; 8] = b"AETSSEQ1";
const SEQUENCE_DIGEST_DOMAIN: &[u8] = b"noticer-aets-public-sequence-v1";
const REFERENCE_DIGEST_DOMAIN: &[u8] = b"noticer-aets-source-reference-artifact-v1";
const REFERENCE_EXECUTABLE_DOMAIN: &[u8] = b"noticer-aets-source-reference-code-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsPublicSequence {
    commands: Box<[ContextCommand]>,
    host_tape: PublicHostTape,
    limits: ExecutionLimits,
    digest: Digest,
}

impl AetsPublicSequence {
    pub fn new(
        compiled: &AetsCompiledQsm,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
        max_commands: usize,
    ) -> Result<Self, AetsReferenceError> {
        if commands.is_empty() || commands.len() > max_commands || max_commands == 0 {
            return Err(AetsReferenceError::CommandCount);
        }
        if limits.fuel == 0
            || limits.max_memory_pages == 0
            || limits.max_host_calls == 0
            || limits.timeout_ms == 0
        {
            return Err(AetsReferenceError::InvalidLimits);
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsReferenceArtifact {
    source_digest: Digest,
    sequence_digest: Digest,
    artifact_digest: Digest,
    run: EngineRunArtifact,
}

impl AetsReferenceArtifact {
    #[must_use]
    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    #[must_use]
    pub const fn sequence_digest(&self) -> Digest {
        self.sequence_digest
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> Digest {
        self.artifact_digest
    }

    #[must_use]
    pub fn run(&self) -> &EngineRunArtifact {
        &self.run
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AetsReferenceUnresolved {
    HostCallBound { required: u64, limit: u64 },
    StateArithmetic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AetsReferenceVerdict {
    Executed(Box<AetsReferenceArtifact>),
    Unresolved(AetsReferenceUnresolved),
}

pub fn evaluate_aets_source_reference(
    compiled: &AetsCompiledQsm,
    sequence: &AetsPublicSequence,
) -> Result<AetsReferenceVerdict, AetsReferenceError> {
    let required_host_calls = u64::try_from(sequence.host_tape().directives().len())
        .map_err(|_| AetsReferenceError::Arithmetic)?;
    if required_host_calls > sequence.limits().max_host_calls {
        return Ok(AetsReferenceVerdict::Unresolved(
            AetsReferenceUnresolved::HostCallBound {
                required: required_host_calls,
                limit: sequence.limits().max_host_calls,
            },
        ));
    }
    let (trace, termination) = expected_trace(compiled, sequence)?;
    let input = ExecutionInput {
        module_sha256: sha256_hex(compiled.wasm_module()),
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
        .map_err(|error| AetsReferenceError::EngineContract(error.to_string()))?;
    let canonical_run = run
        .canonical_json()
        .map_err(|error| AetsReferenceError::EngineContract(error.to_string()))?;
    let mut artifact_bytes = Vec::with_capacity(64 + canonical_run.len());
    artifact_bytes.extend_from_slice(compiled.source_digest().as_bytes());
    artifact_bytes.extend_from_slice(sequence.digest().as_bytes());
    artifact_bytes.extend_from_slice(&canonical_run);
    let artifact = AetsReferenceArtifact {
        source_digest: compiled.source_digest(),
        sequence_digest: sequence.digest(),
        artifact_digest: artifact_digest(REFERENCE_DIGEST_DOMAIN, &artifact_bytes),
        run,
    };
    Ok(AetsReferenceVerdict::Executed(Box::new(artifact)))
}

fn validate_commands(commands: &[ContextCommand]) -> Result<(), AetsReferenceError> {
    let mut stopped = false;
    for command in commands {
        if stopped {
            return Err(AetsReferenceError::CommandAfterStop);
        }
        if command.kind != command.family.command_kind() || command.payload_tag != 0 {
            return Err(AetsReferenceError::NonCanonicalCommand);
        }
        match command.family {
            ContextFamily::Tick | ContextFamily::Retry | ContextFamily::Deadline => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AetsReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::FaultTimeout => validate_fault(command, 1)?,
            ContextFamily::FaultReconnect => validate_fault(command, 2)?,
            ContextFamily::FaultLoss => validate_fault(command, 3)?,
            ContextFamily::Reset | ContextFamily::Handoff | ContextFamily::Stop => {
                if command.service_alias != 0 || command.public_slot != 0 || command.fault != 0 {
                    return Err(AetsReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::ServiceCollusion | ContextFamily::CrossServiceReplay => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AetsReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::Malformed => return Err(AetsReferenceError::NonCanonicalCommand),
        }
        stopped = command.kind == CommandKind::Stop;
    }
    Ok(())
}

fn validate_fault(command: &ContextCommand, expected: u8) -> Result<(), AetsReferenceError> {
    if command.kind != CommandKind::PublicFault
        || command.fault != expected
        || command.service_alias == 0
    {
        Err(AetsReferenceError::NonCanonicalCommand)
    } else {
        Ok(())
    }
}

fn expected_host_tape(
    compiled: &AetsCompiledQsm,
    commands: &[ContextCommand],
) -> Result<PublicHostTape, AetsReferenceError> {
    let known: BTreeSet<u32> = compiled
        .service_codes()
        .iter()
        .map(|mapping| mapping.qsm_alias)
        .collect();
    let placements: BTreeMap<(u32, u64), u16> = compiled
        .action_placements()
        .iter()
        .map(|placement| ((placement.qsm_alias, placement.slot), placement.action))
        .collect();
    let (start, end) = compiled.schedule_range();
    let mut directives = Vec::new();
    for command in commands {
        if !matches!(
            command.kind,
            CommandKind::PublicCall | CommandKind::PublicFault
        ) {
            continue;
        }
        if !known.contains(&command.service_alias)
            || command.public_slot < start
            || command.public_slot > end
        {
            directives.push(HostDirective::new(
                "qseal.public_failure",
                HostOutcome::Continue,
            ));
            continue;
        }
        directives.push(HostDirective::new(
            "qseal.emit_frame",
            HostOutcome::Continue,
        ));
        if command.fault != 0 {
            directives.push(HostDirective::new(
                "qseal.public_failure",
                HostOutcome::Continue,
            ));
        } else if placements.contains_key(&(command.service_alias, command.public_slot)) {
            directives.push(HostDirective::new(
                "qseal.emit_action",
                HostOutcome::Continue,
            ));
        }
    }
    Ok(PublicHostTape::new(directives))
}

fn expected_trace(
    compiled: &AetsCompiledQsm,
    sequence: &AetsPublicSequence,
) -> Result<(Vec<ObservableEvent>, ExecutionTermination), AetsReferenceError> {
    let known: BTreeSet<u32> = compiled
        .service_codes()
        .iter()
        .map(|mapping| mapping.qsm_alias)
        .collect();
    let placements: BTreeMap<(u32, u64), u16> = compiled
        .action_placements()
        .iter()
        .map(|placement| ((placement.qsm_alias, placement.slot), placement.action))
        .collect();
    let (start, end) = compiled.schedule_range();
    let mut trace = Vec::new();
    let mut state = 0_u32;
    let mut final_values = Vec::new();
    for command in sequence.commands() {
        if command.kind == CommandKind::Stop {
            return Ok((trace, ExecutionTermination::Terminated));
        }
        final_values = match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => tick_trace(
                &mut trace,
                &mut state,
                command,
                &known,
                &placements,
                start,
                end,
            )?,
            CommandKind::PublicReset => {
                trace.push(ObservableEvent::ApiCall {
                    export: "qseal.public.reset".to_owned(),
                    arguments: Vec::new(),
                });
                state = 0;
                trace.push(ObservableEvent::Reset { return_code: 0 });
                let values = vec![ScalarValue::I32 { bits: 0 }];
                trace.push(ObservableEvent::ApiReturn {
                    export: "qseal.public.reset".to_owned(),
                    values: values.clone(),
                });
                values
            }
            CommandKind::PublicHandoff => {
                trace.push(ObservableEvent::ApiCall {
                    export: "qseal.public.handoff".to_owned(),
                    arguments: Vec::new(),
                });
                trace.push(ObservableEvent::Handoff {
                    value: u64::from(state),
                });
                let values = vec![ScalarValue::I64 {
                    bits: u64::from(state),
                }];
                trace.push(ObservableEvent::ApiReturn {
                    export: "qseal.public.handoff".to_owned(),
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

#[allow(clippy::too_many_arguments)]
fn tick_trace(
    trace: &mut Vec<ObservableEvent>,
    state: &mut u32,
    command: &ContextCommand,
    known: &BTreeSet<u32>,
    placements: &BTreeMap<(u32, u64), u16>,
    schedule_start: u64,
    schedule_end: u64,
) -> Result<Vec<ScalarValue>, AetsReferenceError> {
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
    let return_code = if !known.contains(&command.service_alias) {
        append_failure(trace, UNKNOWN_SERVICE_FAILURE);
        1
    } else if command.public_slot < schedule_start || command.public_slot > schedule_end {
        append_failure(trace, OUTSIDE_SCHEDULE_FAILURE);
        2
    } else {
        append_frame(trace, command.service_alias, command.public_slot);
        *state = state
            .checked_add(1)
            .ok_or(AetsReferenceError::StateArithmetic)?;
        if command.fault != 0 {
            append_failure(trace, i32::from(command.fault));
            3
        } else {
            if let Some(action) = placements.get(&(command.service_alias, command.public_slot)) {
                append_action(trace, u32::from(*action), command.public_slot);
            }
            0
        }
    };
    let values = vec![ScalarValue::I32 { bits: return_code }];
    trace.push(ObservableEvent::ApiReturn {
        export: export.to_owned(),
        values: values.clone(),
    });
    Ok(values)
}

fn append_frame(trace: &mut Vec<ObservableEvent>, label: u32, slot: u64) {
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

fn append_action(trace: &mut Vec<ObservableEvent>, action: u32, slot: u64) {
    trace.push(ObservableEvent::HostImport {
        import: "qseal.emit_action".to_owned(),
        arguments: vec![
            ScalarValue::I32 { bits: action },
            ScalarValue::I32 { bits: slot as u32 },
        ],
        outcome: HostOutcomeRecord::Continue,
    });
    trace.push(ObservableEvent::EmitAction {
        action,
        slot: u64::from(slot as u32),
        return_code: 0,
    });
}

fn append_failure(trace: &mut Vec<ObservableEvent>, code: i32) {
    trace.push(ObservableEvent::HostImport {
        import: "qseal.public_failure".to_owned(),
        arguments: vec![ScalarValue::I32 { bits: code as u32 }],
        outcome: HostOutcomeRecord::Continue,
    });
    trace.push(ObservableEvent::PublicFailure { code });
}

fn append_public_state_probe(trace: &mut Vec<ObservableEvent>, state: u32) {
    trace.push(ObservableEvent::ApiCall {
        export: "qseal.public.status".to_owned(),
        arguments: Vec::new(),
    });
    trace.push(ObservableEvent::ApiReturn {
        export: "qseal.public.status".to_owned(),
        values: vec![ScalarValue::I32 { bits: state }],
    });
    trace.push(ObservableEvent::PublicState {
        digest_sha256: sha256_hex(&state.to_le_bytes()),
    });
}

fn sequence_digest(
    compiled: &AetsCompiledQsm,
    commands: &[ContextCommand],
    host_tape: &PublicHostTape,
    limits: ExecutionLimits,
) -> Result<Digest, AetsReferenceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SEQUENCE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(compiled.source_digest().as_bytes());
    bytes.extend_from_slice(compiled.module_digest().as_bytes());
    bytes.extend_from_slice(compiled.capsule_digest().as_bytes());
    bytes.extend_from_slice(quotient_seal_abi_v1_hash().as_bytes());
    bytes.extend_from_slice(&limits.fuel.to_le_bytes());
    bytes.extend_from_slice(&limits.max_memory_pages.to_le_bytes());
    bytes.extend_from_slice(&limits.max_host_calls.to_le_bytes());
    bytes.extend_from_slice(&limits.timeout_ms.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(commands.len())
            .map_err(|_| AetsReferenceError::Arithmetic)?
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
            .map_err(|_| AetsReferenceError::Arithmetic)?
            .to_le_bytes(),
    );
    for directive in host_tape.directives() {
        let import = directive.import().as_bytes();
        bytes.extend_from_slice(
            &u16::try_from(import.len())
                .map_err(|_| AetsReferenceError::Arithmetic)?
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

fn source_reference_identity(compiled: &AetsCompiledQsm) -> EngineIdentity {
    let executable = artifact_digest(
        REFERENCE_EXECUTABLE_DOMAIN,
        AETS_SOURCE_REFERENCE_VERSION.as_bytes(),
    );
    EngineIdentity {
        name: "noticer-aets-source-reference".to_owned(),
        version: AETS_SOURCE_REFERENCE_VERSION.to_owned(),
        executable_sha256: hex(executable.as_bytes()),
        adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
        configuration: BTreeMap::from([
            (
                "reference_kind".to_owned(),
                "SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER".to_owned(),
            ),
            (
                "source_digest".to_owned(),
                hex(compiled.source_digest().as_bytes()),
            ),
        ]),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum AetsReferenceError {
    #[error("AETS public sequence command count is empty or exceeds the bound")]
    CommandCount,
    #[error("AETS public sequence resource limits must be nonzero")]
    InvalidLimits,
    #[error("AETS public sequence contains a non-canonical command")]
    NonCanonicalCommand,
    #[error("AETS public sequence contains a command after Stop")]
    CommandAfterStop,
    #[error("AETS reference artifact arithmetic overflow")]
    Arithmetic,
    #[error("AETS reference public state overflow")]
    StateArithmetic,
    #[error("AETS reference engine artifact violated its contract: {0}")]
    EngineContract(String),
}
