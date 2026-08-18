#![forbid(unsafe_code)]

//! Engine-independent execution artifacts for QuotientSeal.
//!
//! This crate freezes the evidence boundary shared by engine adapters. It does
//! not execute WebAssembly and does not treat an unavailable engine as a
//! successful observation.

mod contract;

pub use contract::{
    compute_execution_id, ContextCommandRecord, ContractError, EngineIdentity, EngineRunArtifact,
    EngineRunVerdict, ExecutionInput, ExecutionLimits, ExecutionTermination, HostDirectiveRecord,
    HostFaultRecord, HostOutcomeRecord, HostTapeRecord, InstructionTraceScope, ObservableAxis,
    ObservableEvent, ProtocolConfig, ResourceKind, ScalarValue, TrapClass, VersionPolicy,
    CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION, CROSS_ENGINE_PROTOCOL_SCHEMA_VERSION,
    ENGINE_ADAPTER_CONTRACT_VERSION,
};
