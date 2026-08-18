#![forbid(unsafe_code)]

//! Engine-independent execution artifacts for QuotientSeal.
//!
//! This crate freezes the evidence boundary shared by engine adapters. It does
//! not execute WebAssembly and does not treat an unavailable engine as a
//! successful observation.

mod contract;
mod differential;
mod wasmi_adapter;
mod wasmtime_adapter;

pub use contract::{
    compute_execution_id, ContextCommandRecord, ContractError, EngineIdentity, EngineRunArtifact,
    EngineRunVerdict, ExecutionInput, ExecutionLimits, ExecutionTermination, HostDirectiveRecord,
    HostFaultRecord, HostOutcomeRecord, HostTapeRecord, InstructionTraceScope, ObservableAxis,
    ObservableEvent, ProtocolConfig, ResourceKind, ScalarValue, TrapClass, VersionPolicy,
    CROSS_ENGINE_ARTIFACT_SCHEMA_VERSION, CROSS_ENGINE_PROTOCOL_SCHEMA_VERSION,
    ENGINE_ADAPTER_CONTRACT_VERSION,
};
pub use differential::{
    ComparisonPoint, DifferentialCounterexample, DifferentialCounterexampleKind,
    DifferentialOracle, DifferentialOracleArtifact, DifferentialOracleError, DifferentialVerdict,
    UnresolvedEvidence, DIFFERENTIAL_ORACLE_ARTIFACT_SCHEMA_VERSION, DIFFERENTIAL_ORACLE_VERSION,
    REFERENCE_ENGINE_NAME,
};
pub use wasmi_adapter::{
    WasmiAdapter, WasmiAdapterError, WASMI_ADAPTER_PROFILE_VERSION, WASMI_CRATE_VERSION,
};
pub use wasmtime_adapter::{
    WasmtimeAdapter, WasmtimeAdapterError, WASMTIME_ADAPTER_PROFILE_VERSION, WASMTIME_CRATE_VERSION,
};
