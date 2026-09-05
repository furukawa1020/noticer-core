#![forbid(unsafe_code)]

//! Deterministic exhaustive synthesis for small AQRS models.
//!
//! This crate is the solver-free reference backend. It enumerates canonical
//! finite-state release machines and delegates every security decision to the
//! independent K6-04 product checker.

mod blocker;
mod model;
mod search;
pub mod session;

pub use blocker::{
    synthesis_problem_sha256, BlockerAssignmentRecord, BlockerAudit, BlockerClass, TypedBlocker,
    TypedBlockerArtifact, TypedBlockerError, TYPED_BLOCKER_SCHEMA_V1,
};
pub use model::{
    MachineCell, PlantPair, PlantState, PlantTransition, ProblemError, ReleaseMachine,
    SynthesisCost, SynthesisProblem,
};
pub use search::{
    blocking_clause_from_counterexample, find_feasible, optimize_cost, BlockingClause,
    DecisionAssignment, InconclusiveReason, SearchStats, SynthesisError, SynthesisLimits,
    SynthesisOutcome, SynthesisReport, UnrealizableReport,
};
