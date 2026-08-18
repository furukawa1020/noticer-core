use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use quotient_seal_context::ContextCommand;
use quotient_seal_small_step::{HostOutcome, PublicHostFault, PublicHostTape};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const CROSS_ENGINE_PROTOCOL_SCHEMA_VERSION: &str = "quotient-seal-cross-engine-protocol/v1";
pub const CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION: &str = "quotient-seal-engine-run/v1";
pub const ENGINE_ADAPTER_CONTRACT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VersionPolicy {
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstructionTraceScope {
    ReferenceInterpreterOnly,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservableAxis {
    Output,
    PublicState,
    Trap,
    Return,
    HostImport,
    Reset,
    Handoff,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolConfig {
    pub schema_version: String,
    pub artifact_schema_version: String,
    pub required_engines: Vec<String>,
    pub version_policy: VersionPolicy,
    pub missing_engine_policy: EngineRunVerdict,
    pub instruction_trace_scope: InstructionTraceScope,
    pub observer_surface: Vec<ObservableAxis>,
}

impl ProtocolConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ContractError> {
        let config: Self = serde_json::from_slice(bytes)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CROSS_ENGINE_PROTOCOL_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: CROSS_ENGINE_PROTOCOL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.artifact_schema_version != CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION,
                actual: self.artifact_schema_version.clone(),
            });
        }
        if self.version_policy != VersionPolicy::Exact
            || self.missing_engine_policy != EngineRunVerdict::Unresolved
            || self.instruction_trace_scope != InstructionTraceScope::ReferenceInterpreterOnly
        {
            return Err(ContractError::UnsafeProtocolPolicy);
        }
        let engines: BTreeSet<&str> = self.required_engines.iter().map(String::as_str).collect();
        if engines.len() != self.required_engines.len()
            || !engines.contains("wasmi")
            || !engines.contains("wasmtime")
        {
            return Err(ContractError::InvalidEngineSet);
        }
        let axes: BTreeSet<ObservableAxis> = self.observer_surface.iter().copied().collect();
        if axes.len() != ObservableAxis::ALL.len()
            || !ObservableAxis::ALL.iter().all(|axis| axes.contains(axis))
        {
            return Err(ContractError::InvalidObserverSurface);
        }
        Ok(())
    }
}

impl ObservableAxis {
    pub const ALL: [Self; 7] = [
        Self::Output,
        Self::PublicState,
        Self::Trap,
        Self::Return,
        Self::HostImport,
        Self::Reset,
        Self::Handoff,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    pub name: String,
    pub version: String,
    pub executable_sha256: String,
    pub adapter_contract_version: u16,
    pub configuration: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub fuel: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCommandRecord {
    pub family_code: u8,
    pub kind_code: u8,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

impl From<&ContextCommand> for ContextCommandRecord {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostFaultRecord {
    Timeout,
    Reconnect,
    Loss,
    Denied,
}

impl From<PublicHostFault> for HostFaultRecord {
    fn from(fault: PublicHostFault) -> Self {
        match fault {
            PublicHostFault::Timeout => Self::Timeout,
            PublicHostFault::Reconnect => Self::Reconnect,
            PublicHostFault::Loss => Self::Loss,
            PublicHostFault::Denied => Self::Denied,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostOutcomeRecord {
    Continue,
    Terminate,
    Fault { fault: HostFaultRecord },
}

impl From<HostOutcome> for HostOutcomeRecord {
    fn from(outcome: HostOutcome) -> Self {
        match outcome {
            HostOutcome::Continue => Self::Continue,
            HostOutcome::Terminate => Self::Terminate,
            HostOutcome::Fault(fault) => Self::Fault {
                fault: fault.into(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDirectiveRecord {
    pub import: String,
    pub outcome: HostOutcomeRecord,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTapeRecord {
    pub directives: Vec<HostDirectiveRecord>,
}

impl From<&PublicHostTape> for HostTapeRecord {
    fn from(tape: &PublicHostTape) -> Self {
        Self {
            directives: tape
                .directives()
                .iter()
                .map(|directive| HostDirectiveRecord {
                    import: directive.import().to_owned(),
                    outcome: directive.outcome().into(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    pub module_sha256: String,
    pub abi_sha256: String,
    pub engine: EngineIdentity,
    pub host_tape: HostTapeRecord,
    pub context_sequence: Vec<ContextCommandRecord>,
    pub limits: ExecutionLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScalarValue {
    I32 { bits: u32 },
    I64 { bits: u64 },
    F32Bits { bits: u32 },
    F64Bits { bits: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservableEvent {
    ApiCall {
        export: String,
        arguments: Vec<ScalarValue>,
    },
    ApiReturn {
        export: String,
        values: Vec<ScalarValue>,
    },
    EmitFrame {
        label: u32,
        slot: u64,
        value: i32,
    },
    EmitAction {
        action: u32,
        slot: u64,
        return_code: i32,
    },
    PublicFailure {
        code: i32,
    },
    HostImport {
        import: String,
        arguments: Vec<ScalarValue>,
        outcome: HostOutcomeRecord,
    },
    Reset {
        return_code: i32,
    },
    Handoff {
        value: u64,
    },
    PublicState {
        digest_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrapClass {
    Unreachable,
    IntegerDivideByZero,
    IntegerOverflow,
    MemoryOutOfBounds,
    InvalidConversion,
    HostFault,
    EngineSpecific,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceKind {
    Fuel,
    Memory,
    HostCalls,
    EventLog,
    CallDepth,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionTermination {
    Returned {
        values: Vec<ScalarValue>,
    },
    Trapped {
        class: TrapClass,
        engine_code: String,
        detail_sha256: String,
    },
    Terminated,
    InvalidModule {
        reason_code: String,
        detail_sha256: String,
    },
    Unsupported {
        feature: String,
    },
    TimedOut {
        limit_ms: u64,
    },
    ResourceExhausted {
        resource: ResourceKind,
        limit: u64,
        observed: Option<u64>,
    },
    EngineFailure {
        stage: String,
        exit_code: Option<i32>,
        detail_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineRunVerdict {
    Executed,
    Rejected,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRunArtifact {
    pub schema_version: String,
    pub execution_id_sha256: String,
    pub input: ExecutionInput,
    pub trace: Vec<ObservableEvent>,
    pub termination: ExecutionTermination,
    pub verdict: EngineRunVerdict,
}

impl EngineRunArtifact {
    pub fn new(
        input: ExecutionInput,
        trace: Vec<ObservableEvent>,
        termination: ExecutionTermination,
        verdict: EngineRunVerdict,
    ) -> Result<Self, ContractError> {
        let execution_id_sha256 = compute_execution_id(&input)?;
        let artifact = Self {
            schema_version: CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION.to_owned(),
            execution_id_sha256,
            input,
            trace,
            termination,
            verdict,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ContractError> {
        let artifact: Self = serde_json::from_slice(bytes)?;
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        validate_input(&self.input)?;
        validate_termination(&self.termination)?;
        for event in &self.trace {
            if let ObservableEvent::PublicState { digest_sha256 } = event {
                validate_sha256("public state digest", digest_sha256)?;
            }
        }
        let coherent = matches!(
            (&self.verdict, &self.termination),
            (
                EngineRunVerdict::Executed,
                ExecutionTermination::Returned { .. }
                    | ExecutionTermination::Trapped { .. }
                    | ExecutionTermination::Terminated
            ) | (
                EngineRunVerdict::Rejected,
                ExecutionTermination::InvalidModule { .. }
            ) | (
                EngineRunVerdict::Unresolved,
                ExecutionTermination::Unsupported { .. }
                    | ExecutionTermination::TimedOut { .. }
                    | ExecutionTermination::ResourceExhausted { .. }
                    | ExecutionTermination::EngineFailure { .. }
            )
        );
        if !coherent {
            return Err(ContractError::VerdictTerminationMismatch);
        }
        let expected = compute_execution_id(&self.input)?;
        if self.execution_id_sha256 != expected {
            return Err(ContractError::ExecutionIdMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn artifact_sha256(&self) -> Result<String, ContractError> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    pub fn write_json(&self, path: &Path) -> Result<(), ContractError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

pub fn compute_execution_id(input: &ExecutionInput) -> Result<String, ContractError> {
    validate_input(input)?;
    #[derive(Serialize)]
    struct IdentityPayload<'a> {
        schema_version: &'static str,
        input: &'a ExecutionInput,
    }
    let payload = IdentityPayload {
        schema_version: CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION,
        input,
    };
    Ok(sha256_hex(&serde_json::to_vec(&payload)?))
}

fn validate_input(input: &ExecutionInput) -> Result<(), ContractError> {
    validate_sha256("module digest", &input.module_sha256)?;
    validate_sha256("ABI digest", &input.abi_sha256)?;
    validate_sha256("engine executable digest", &input.engine.executable_sha256)?;
    if input.engine.name.trim().is_empty() || input.engine.version.trim().is_empty() {
        return Err(ContractError::EmptyEngineIdentity);
    }
    if input.engine.adapter_contract_version != ENGINE_ADAPTER_CONTRACT_VERSION {
        return Err(ContractError::AdapterContractVersion {
            expected: ENGINE_ADAPTER_CONTRACT_VERSION,
            actual: input.engine.adapter_contract_version,
        });
    }
    if input.engine.configuration.is_empty() {
        return Err(ContractError::EmptyEngineConfiguration);
    }
    if input.limits.fuel == 0
        || input.limits.max_memory_pages == 0
        || input.limits.max_host_calls == 0
        || input.limits.timeout_ms == 0
    {
        return Err(ContractError::InvalidLimits);
    }
    if input.context_sequence.is_empty() {
        return Err(ContractError::EmptyContextSequence);
    }
    if input
        .host_tape
        .directives
        .iter()
        .any(|directive| directive.import.trim().is_empty())
    {
        return Err(ContractError::EmptyHostImport);
    }
    Ok(())
}

fn validate_termination(termination: &ExecutionTermination) -> Result<(), ContractError> {
    match termination {
        ExecutionTermination::Trapped {
            engine_code,
            detail_sha256,
            ..
        } => {
            if engine_code.trim().is_empty() {
                return Err(ContractError::EmptyTerminationDetail);
            }
            validate_sha256("trap detail", detail_sha256)
        }
        ExecutionTermination::InvalidModule {
            reason_code,
            detail_sha256,
        } => {
            if reason_code.trim().is_empty() {
                return Err(ContractError::EmptyTerminationDetail);
            }
            validate_sha256("invalid module detail", detail_sha256)
        }
        ExecutionTermination::Unsupported { feature } => {
            if feature.trim().is_empty() {
                Err(ContractError::EmptyTerminationDetail)
            } else {
                Ok(())
            }
        }
        ExecutionTermination::TimedOut { limit_ms } if *limit_ms == 0 => {
            Err(ContractError::InvalidLimits)
        }
        ExecutionTermination::ResourceExhausted { limit, .. } if *limit == 0 => {
            Err(ContractError::InvalidLimits)
        }
        ExecutionTermination::EngineFailure {
            stage,
            detail_sha256,
            ..
        } => {
            if stage.trim().is_empty() {
                return Err(ContractError::EmptyTerminationDetail);
            }
            validate_sha256("engine failure detail", detail_sha256)
        }
        _ => Ok(()),
    }
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidSha256 { field });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("protocol policy would weaken the fail-closed boundary")]
    UnsafeProtocolPolicy,
    #[error("required engine set must contain distinct wasmi and wasmtime entries")]
    InvalidEngineSet,
    #[error("observer surface is incomplete or contains duplicates")]
    InvalidObserverSurface,
    #[error("engine identity contains an empty name or version")]
    EmptyEngineIdentity,
    #[error("engine configuration must not be empty")]
    EmptyEngineConfiguration,
    #[error("adapter contract version mismatch: expected {expected}, got {actual}")]
    AdapterContractVersion { expected: u16, actual: u16 },
    #[error("execution limits must be non-zero")]
    InvalidLimits,
    #[error("context sequence must not be empty")]
    EmptyContextSequence,
    #[error("host import name must not be empty")]
    EmptyHostImport,
    #[error("invalid lowercase SHA-256 in {field}")]
    InvalidSha256 { field: &'static str },
    #[error("termination detail must not be empty")]
    EmptyTerminationDetail,
    #[error("engine verdict and termination are inconsistent")]
    VerdictTerminationMismatch,
    #[error("execution ID does not bind the complete execution input")]
    ExecutionIdMismatch,
    #[error("JSON contract error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact I/O error: {0}")]
    Io(#[from] std::io::Error),
}
