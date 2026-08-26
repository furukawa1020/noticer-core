#![forbid(unsafe_code)]

//! Generic action-quotient robust-compilation benchmark contracts.

mod contract;

pub use contract::{
    frozen_registry, ActionClass, BenchmarkCaseInput, BenchmarkExpectedVerdict,
    BenchmarkFamilyContract, BenchmarkFamilyId, BenchmarkFamilyKind, BenchmarkInconclusiveReason,
    BenchmarkInputError, BenchmarkObserverContract, BenchmarkOutcome, BenchmarkRegistry,
    BenchmarkResourceBudget, EvaluatorKind, PrivatePredicateClass, BENCHMARK_FAMILY_COUNT,
    GENERIC_BENCHMARK_MAGIC, GENERIC_BENCHMARK_SCHEMA, HARDWARE_STATUS,
};
