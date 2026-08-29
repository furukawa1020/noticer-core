#![forbid(unsafe_code)]

//! Typed performance and resource measurement contracts for QuotientSeal.

mod contract;

pub use contract::{
    BenchmarkCase, BenchmarkRunConfig, CpuCountBucket, HardwareStatus, MachineArchitecture,
    MeasurementCampaign, MeasurementContractError, MeasurementEvidenceOrigin,
    MeasurementFailureReason, MeasurementInconclusiveReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementSample, MeasurementStage, MeasurementUnit, MemoryBucket,
    OsFamily, SanitizedMachineMetadata, TimerKind, PERFORMANCE_CAMPAIGN_SCHEMA,
    PERFORMANCE_SAMPLE_SCHEMA,
};
