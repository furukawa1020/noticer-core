#![forbid(unsafe_code)]

//! Generic action-quotient robust-compilation benchmark contracts.

mod contract;
mod negative;
mod split_gate;
mod valid;

pub use contract::{
    frozen_registry, ActionClass, BenchmarkCaseInput, BenchmarkExpectedVerdict,
    BenchmarkFamilyContract, BenchmarkFamilyId, BenchmarkFamilyKind, BenchmarkInconclusiveReason,
    BenchmarkInputError, BenchmarkObserverContract, BenchmarkOutcome, BenchmarkRegistry,
    BenchmarkResourceBudget, EvaluatorKind, PrivatePredicateClass, BENCHMARK_FAMILY_COUNT,
    GENERIC_BENCHMARK_MAGIC, GENERIC_BENCHMARK_SCHEMA, HARDWARE_STATUS,
};
pub use negative::{
    execute_negative_family, generate_negative_families, NegativeDifference,
    NegativeDifferenceKind, NegativeExecutionReceipt, NegativeFamilyError, NegativeFamilyFixture,
    NegativeMutationClass, NegativeObserverSurface, NegativeVariant, NEGATIVE_FAMILY_COUNT,
    NEGATIVE_VARIANTS_PER_FAMILY,
};
pub use split_gate::{
    build_family_split, evaluate_held_out_comparison, BenchmarkComparisonArtifact,
    BenchmarkComparisonError, BenchmarkComparisonRecord, BenchmarkComparisonSummary,
    BenchmarkGateVerdict, BenchmarkSplit, FamilySplitAssignment, FamilySplitPlan,
    BASELINE_SPECIFICATION, COMPARISON_CASE_COUNT, FULL_QUOTIENT_SEAL_SPECIFICATION,
};
pub use valid::{
    execute_valid_family, generate_valid_families, SyntheticPrivateHistory, ValidExecutionReceipt,
    ValidFamilyError, ValidFamilyFixture, ValidPublicEvent, ValidSourceOp, ValidVariant,
    VALID_FAMILY_COUNT, VALID_VARIANTS_PER_FAMILY,
};
