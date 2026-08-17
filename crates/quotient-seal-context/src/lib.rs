#![forbid(unsafe_code)]

//! Finite adversarial-context product checking for QuotientSeal.
//!
//! The checker consumes a successful K8-05 relation verdict as a mandatory
//! gate. It then closes finite reactive host contexts over paired private
//! worlds and emits a shortest, reproducible counterexample when traces split.

mod checker;
mod model;

pub use checker::{check_context_product, check_context_product_profile};
pub use model::{
    project_trace, CallRecord, CommandKind, ContextAutomaton, ContextCommand, ContextFamily,
    ContextTransition, ContextViolation, ContextViolationKind, DivergenceKind, EventKind,
    ExecutionBoundary, InductionObligations, InitialRun, Observation, ObserverProfile,
    OracleCounterexample, OracleInconclusive, OracleResult, ProductCheckReport,
    ProductCounterexample, ProductInconclusive, ProductLimits, ProductVerdict, RelationBinding,
    RunState, RunStep, SourceEvent, SourceEventKind, TargetEvent, ValidatedProductSystem, World,
    CONTEXT_FAMILY_COUNT, CONTEXT_PRODUCT_FORMAT_VERSION, MAX_PREFIX_HARD_LIMIT,
    QUOTIENT_SEAL_CONTEXT_PRODUCT_V1,
};
