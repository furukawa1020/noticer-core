#![forbid(unsafe_code)]

//! Typed performance and resource measurement contracts for QuotientSeal.

mod bundle;
mod contract;
mod gate;
mod runner;
mod statistics;

pub use bundle::{
    write_reproduction_artifacts, GateOutcomeCounts, PerformanceBundleError,
    PerformanceBundleSummary, PerformanceReproductionBundle, PERFORMANCE_BUNDLE_SCHEMA,
};
pub use contract::{
    BenchmarkCase, BenchmarkRunConfig, CpuCountBucket, HardwareStatus, MachineArchitecture,
    MeasurementCampaign, MeasurementContractError, MeasurementEvidenceOrigin,
    MeasurementFailureReason, MeasurementInconclusiveReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementSample, MeasurementStage, MeasurementUnit, MemoryBucket,
    OsFamily, SanitizedMachineMetadata, TimerKind, PERFORMANCE_CAMPAIGN_SCHEMA,
    PERFORMANCE_SAMPLE_SCHEMA,
};
pub use gate::{
    evaluate_budget, BudgetConstraint, BudgetPlan, BudgetRule, BudgetStatistic, GateEvaluation,
    GateInconclusiveReason, GateRuleOutcome, PerformanceGateArtifact, PerformanceGateError,
    PerformanceGateVerdict, GATE_ARTIFACT_SCHEMA, GATE_PLAN_SCHEMA,
};
pub use runner::{
    run_software_fixture, DeterministicFixturePlan, FixtureInvocation, FixtureInvocationPhase,
    FixtureInvocationRecord, FixtureRunArtifact, FixtureRunSummary, FixtureRunnerConfig,
    FixtureRunnerError, FixtureTask, SoftwareFixtureBenchmark, FIXTURE_PLAN_SCHEMA,
    FIXTURE_RUN_SCHEMA,
};
pub use statistics::{
    aggregate_campaigns, AttackAucAggregate, AttackAucKey, AttackAucStatus, AttackClass,
    AttackLabelBinding, CensoredCounts, EffectSizeAggregate, EffectSizePair, EffectSizeStatus,
    FailureReasonCount, InconclusiveReasonCount, MetricAggregate, MetricGroupKey,
    MetricStatisticsStatus, StatisticsArtifact, StatisticsError, StatisticsInconclusiveReason,
    StatisticsPlan, STATISTICS_ARTIFACT_SCHEMA, STATISTICS_PLAN_SCHEMA,
};
