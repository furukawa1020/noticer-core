use std::collections::BTreeMap;

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

const UNKNOWN_PUBLIC_EVENT_FAILURE: i32 = 0x52fe;
const OUT_OF_ORDER_EVENT_FAILURE: i32 = 0x52ff;
use crate::{AplotCompiledQsm, AplotPublicEventKind};

pub const APLOT_SOURCE_REFERENCE_VERSION: &str = "noticer-aplot-source-reference/v1";
const SEQUENCE_MAGIC: &[u8; 8] = b"APLSEQ01";
const SEQUENCE_DIGEST_DOMAIN: &[u8] = b"noticer-aplot-public-sequence-v1";
const REFERENCE_DIGEST_DOMAIN: &[u8] = b"noticer-aplot-source-reference-artifact-v1";
const REFERENCE_EXECUTABLE_DOMAIN: &[u8] = b"noticer-aplot-source-reference-code-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotPublicSequence {
    commands: Box<[ContextCommand]>,
    host_tape: PublicHostTape,
    limits: ExecutionLimits,
    digest: Digest,
}

impl AplotPublicSequence {
    pub fn new(
        compiled: &AplotCompiledQsm,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
        max_commands: usize,
    ) -> Result<Self, AplotReferenceError> {
        if commands.is_empty() || commands.len() > max_commands || max_commands == 0 {
            return Err(AplotReferenceError::CommandCount);
        }
        if limits.fuel == 0
            || limits.max_memory_pages == 0
            || limits.max_host_calls == 0
            || limits.timeout_ms == 0
        {
            return Err(AplotReferenceError::InvalidLimits);
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
pub struct AplotReferenceArtifact {
    source_digest: Digest,
    sequence_digest: Digest,
    artifact_digest: Digest,
    run: EngineRunArtifact,
}

impl AplotReferenceArtifact {
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
pub enum AplotReferenceUnresolved {
    HostCallBound { required: u64, limit: u64 },
    StateArithmetic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AplotReferenceVerdict {
    Executed(Box<AplotReferenceArtifact>),
    Unresolved(AplotReferenceUnresolved),
}

pub fn evaluate_aplot_source_reference(
    compiled: &AplotCompiledQsm,
    sequence: &AplotPublicSequence,
) -> Result<AplotReferenceVerdict, AplotReferenceError> {
    let required_host_calls = u64::try_from(sequence.host_tape().directives().len())
        .map_err(|_| AplotReferenceError::Arithmetic)?;
    if required_host_calls > sequence.limits().max_host_calls {
        return Ok(AplotReferenceVerdict::Unresolved(
            AplotReferenceUnresolved::HostCallBound {
                required: required_host_calls,
                limit: sequence.limits().max_host_calls,
            },
        ));
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
        .map_err(|error| AplotReferenceError::EngineContract(error.to_string()))?;
    let canonical_run = run
        .canonical_json()
        .map_err(|error| AplotReferenceError::EngineContract(error.to_string()))?;
    let mut artifact_bytes = Vec::with_capacity(64 + canonical_run.len());
    artifact_bytes.extend_from_slice(compiled.binding().source_digest.as_bytes());
    artifact_bytes.extend_from_slice(sequence.digest().as_bytes());
    artifact_bytes.extend_from_slice(&canonical_run);
    let artifact = AplotReferenceArtifact {
        source_digest: compiled.binding().source_digest,
        sequence_digest: sequence.digest(),
        artifact_digest: artifact_digest(REFERENCE_DIGEST_DOMAIN, &artifact_bytes),
        run,
    };
    Ok(AplotReferenceVerdict::Executed(Box::new(artifact)))
}

fn validate_commands(commands: &[ContextCommand]) -> Result<(), AplotReferenceError> {
    let mut stopped = false;
    for command in commands {
        if stopped {
            return Err(AplotReferenceError::CommandAfterStop);
        }
        if command.kind != command.family.command_kind() || command.payload_tag != 0 {
            return Err(AplotReferenceError::NonCanonicalCommand);
        }
        match command.family {
            ContextFamily::Tick | ContextFamily::Deadline => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AplotReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::FaultTimeout => validate_fault(command, 1)?,
            ContextFamily::FaultReconnect => validate_fault(command, 2)?,
            ContextFamily::FaultLoss => validate_fault(command, 3)?,
            ContextFamily::Reset | ContextFamily::Handoff | ContextFamily::Stop => {
                if command.service_alias != 0 || command.public_slot != 0 || command.fault != 0 {
                    return Err(AplotReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::ServiceCollusion | ContextFamily::CrossServiceReplay => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AplotReferenceError::NonCanonicalCommand);
                }
            }
            ContextFamily::Retry | ContextFamily::Malformed => {
                return Err(AplotReferenceError::NonCanonicalCommand)
            }
        }
        stopped = command.kind == CommandKind::Stop;
    }
    Ok(())
}

fn validate_fault(command: &ContextCommand, expected: u8) -> Result<(), AplotReferenceError> {
    if command.kind != CommandKind::PublicFault
        || command.fault != expected
        || command.service_alias == 0
    {
        Err(AplotReferenceError::NonCanonicalCommand)
    } else {
        Ok(())
    }
}

fn expected_host_tape(
    compiled: &AplotCompiledQsm,
    commands: &[ContextCommand],
) -> Result<PublicHostTape, AplotReferenceError> {
    let events = compiled
        .events()
        .iter()
        .map(|event| ((event.qsm_alias, event.public_step), event))
        .collect::<BTreeMap<_, _>>();
    let mut directives = Vec::new();
    let mut cursor = u64::MAX;
    for command in commands {
        match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => {
                let Some(event) = events.get(&(command.service_alias, command.public_slot)) else {
                    directives.push(HostDirective::new(
                        "qseal.public_failure",
                        HostOutcome::Continue,
                    ));
                    continue;
                };
                if command.public_slot != cursor.wrapping_add(1) {
                    directives.push(HostDirective::new(
                        "qseal.public_failure",
                        HostOutcome::Continue,
                    ));
                    continue;
                }
                cursor = command.public_slot;
                if event.kind == AplotPublicEventKind::FragmentAttempt {
                    directives.push(HostDirective::new(
                        "qseal.emit_frame",
                        HostOutcome::Continue,
                    ));
                }
                if event.declared_fault_code != 0 {
                    directives.push(HostDirective::new(
                        "qseal.public_failure",
                        HostOutcome::Continue,
                    ));
                }
                if command.fault != 0 {
                    directives.push(HostDirective::new(
                        "qseal.public_failure",
                        HostOutcome::Continue,
                    ));
                }
            }
            CommandKind::PublicReset => cursor = u64::MAX,
            CommandKind::PublicHandoff | CommandKind::Stop => {}
        }
    }
    Ok(PublicHostTape::new(directives))
}
fn expected_trace(
    compiled: &AplotCompiledQsm,
    sequence: &AplotPublicSequence,
) -> Result<(Vec<ObservableEvent>, ExecutionTermination), AplotReferenceError> {
    let events = compiled
        .events()
        .iter()
        .map(|event| ((event.qsm_alias, event.public_step), event))
        .collect::<BTreeMap<_, _>>();
    let mut trace = Vec::new();
    let mut cursor = u64::MAX;
    let mut final_values = Vec::new();
    for command in sequence.commands() {
        if command.kind == CommandKind::Stop {
            return Ok((trace, ExecutionTermination::Terminated));
        }
        final_values = match command.kind {
            CommandKind::PublicCall | CommandKind::PublicFault => {
                tick_trace(&mut trace, &mut cursor, command, &events)?
            }
            CommandKind::PublicReset => {
                trace.push(ObservableEvent::ApiCall {
                    export: "qseal.public.reset".to_owned(),
                    arguments: Vec::new(),
                });
                cursor = u64::MAX;
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
                trace.push(ObservableEvent::Handoff { value: cursor });
                let values = vec![ScalarValue::I64 { bits: cursor }];
                trace.push(ObservableEvent::ApiReturn {
                    export: "qseal.public.handoff".to_owned(),
                    values: values.clone(),
                });
                values
            }
            CommandKind::Stop => unreachable!("handled above"),
        };
        append_public_state_probe(&mut trace);
    }
    Ok((
        trace,
        ExecutionTermination::Returned {
            values: final_values,
        },
    ))
}
fn tick_trace(
    trace: &mut Vec<ObservableEvent>,
    cursor: &mut u64,
    command: &ContextCommand,
    events: &BTreeMap<(u32, u64), &crate::AplotEventPlacement>,
) -> Result<Vec<ScalarValue>, AplotReferenceError> {
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
    if let Some(event) = events.get(&(command.service_alias, command.public_slot)) {
        if command.public_slot != cursor.wrapping_add(1) {
            append_failure(trace, OUT_OF_ORDER_EVENT_FAILURE);
        } else {
            *cursor = command.public_slot;
            if event.kind == AplotPublicEventKind::FragmentAttempt {
                append_frame(trace, command.service_alias, command.public_slot);
            }
            if event.declared_fault_code != 0 {
                append_failure(trace, event.declared_fault_code);
            }
            if command.fault != 0 {
                append_failure(trace, i32::from(command.fault));
            }
        }
    } else {
        append_failure(trace, UNKNOWN_PUBLIC_EVENT_FAILURE);
    }
    let values = vec![ScalarValue::I32 { bits: 0 }];
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

fn append_failure(trace: &mut Vec<ObservableEvent>, code: i32) {
    trace.push(ObservableEvent::HostImport {
        import: "qseal.public_failure".to_owned(),
        arguments: vec![ScalarValue::I32 { bits: code as u32 }],
        outcome: HostOutcomeRecord::Continue,
    });
    trace.push(ObservableEvent::PublicFailure { code });
}

fn append_public_state_probe(trace: &mut Vec<ObservableEvent>) {
    let state = 0_u32;
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
    compiled: &AplotCompiledQsm,
    commands: &[ContextCommand],
    host_tape: &PublicHostTape,
    limits: ExecutionLimits,
) -> Result<Digest, AplotReferenceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SEQUENCE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(compiled.binding().source_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().module_digest.as_bytes());
    bytes.extend_from_slice(compiled.binding().capsule_digest.as_bytes());
    bytes.extend_from_slice(quotient_seal_abi_v1_hash().as_bytes());
    bytes.extend_from_slice(&limits.fuel.to_le_bytes());
    bytes.extend_from_slice(&limits.max_memory_pages.to_le_bytes());
    bytes.extend_from_slice(&limits.max_host_calls.to_le_bytes());
    bytes.extend_from_slice(&limits.timeout_ms.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(commands.len())
            .map_err(|_| AplotReferenceError::Arithmetic)?
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
            .map_err(|_| AplotReferenceError::Arithmetic)?
            .to_le_bytes(),
    );
    for directive in host_tape.directives() {
        let import = directive.import().as_bytes();
        bytes.extend_from_slice(
            &u16::try_from(import.len())
                .map_err(|_| AplotReferenceError::Arithmetic)?
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

fn source_reference_identity(compiled: &AplotCompiledQsm) -> EngineIdentity {
    let executable = artifact_digest(
        REFERENCE_EXECUTABLE_DOMAIN,
        APLOT_SOURCE_REFERENCE_VERSION.as_bytes(),
    );
    EngineIdentity {
        name: "noticer-aplot-source-reference".to_owned(),
        version: APLOT_SOURCE_REFERENCE_VERSION.to_owned(),
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
pub enum AplotReferenceError {
    #[error("APLOT public sequence command count is empty or exceeds the bound")]
    CommandCount,
    #[error("APLOT public sequence resource limits must be nonzero")]
    InvalidLimits,
    #[error("APLOT public sequence contains a non-canonical command")]
    NonCanonicalCommand,
    #[error("APLOT public sequence contains a command after Stop")]
    CommandAfterStop,
    #[error("APLOT reference artifact arithmetic overflow")]
    Arithmetic,
    #[error("APLOT reference public state overflow")]
    StateArithmetic,
    #[error("APLOT reference engine artifact violated its contract: {0}")]
    EngineContract(String),
}
